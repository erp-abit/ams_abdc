import { useEffect, useState } from 'react';
import * as XLSX from 'xlsx-js-style';
import './LessonPlansReport.css';

async function request(url) {
  const response = await fetch(url, { headers: { Authorization: `Bearer ${localStorage.getItem('abit_session')}` } });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || 'Unable to load Lesson Plans Report.');
  return body;
}

export default function LessonPlansReport() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [subject, setSubject] = useState('');
  const [faculty, setFaculty] = useState('');
  const [downloading, setDownloading] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  useEffect(() => {
    let active = true;
    request('/api/lesson-plans').then(body => { if (active) setRows(body.assignments || []); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);
  const subjectName = row => `${row.subject_name}${row.subject_code ? ` (${row.subject_code})` : ''}`;
  const subjects = [...new Set(rows.map(subjectName))].sort();
  const faculties = [...new Map(rows.map(row => [String(row.faculty_employee_id), row.faculty_name])).entries()].sort((a, b) => a[1].localeCompare(b[1]));
  const visible = rows.filter(row => (!subject || subjectName(row) === subject) && (!faculty || String(row.faculty_employee_id) === faculty));
  const pageCount = Math.max(1, Math.ceil(visible.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const start = (currentPage - 1) * pageSize;
  const pageRows = visible.slice(start, start + pageSize);
  async function download(row) {
    setDownloading(row.id);
    setError('');
    try {
      const detail = await request(`/api/lesson-plans/${row.id}`);
      if (!detail.topics.length) throw new Error('This Lesson Plan no longer contains lessons. Refresh the report.');
      const values = [
        ['Subject', subjectName(row)], ['Faculty', row.faculty_name], ['Academic Year', row.academic_year],
        ['Batch', row.programme_batch], ['Semester', row.semester_name], ['Section', row.section_name], [],
        ['Lesson', 'Topics', 'CO', 'Book', 'Page From', 'Page To', 'Periods', 'PPT Required', 'Video URL', 'Status'],
        ...detail.topics.map(topic => [topic.lesson_number, topic.topic_description, (topic.co_codes || [topic.co_code]).filter(Boolean).join(' | '), topic.book_title || '', topic.page_from ?? '', topic.page_to ?? '', topic.planned_periods, topic.ppt_required ? 'Yes' : 'No', topic.video_url || '', topic.topic_status])
      ];
      const sheet = XLSX.utils.aoa_to_sheet(values);
      sheet['!cols'] = [12, 65, 22, 35, 12, 12, 12, 16, 40, 18].map(wch => ({ wch }));
      const book = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(book, sheet, 'Lesson Plan');
      XLSX.writeFile(book, `lesson-plan-${row.subject_code}-${row.id}.xlsx`.replace(/[<>:"/\\|?*]/g, '-'));
    } catch (err) { setError(err.message); }
    finally { setDownloading(null); }
  }
  return <section className="lesson-plans-report" aria-label="Lesson Plans Report">
    {error && <p role="alert" className="lesson-plans-report-error">{error}</p>}
    <div className="lesson-plans-report-scroll"><table>
      <colgroup><col className="lesson-report-subject"/><col className="lesson-report-faculty"/><col/><col/></colgroup>
      <thead><tr><th scope="col">Subject Name</th><th scope="col">Faculty Name</th><th scope="col">No. of Lessons</th><th scope="col">Download Lesson Plan</th></tr>
        <tr><th><select aria-label="Filter Subject Name" value={subject} onChange={e => { setSubject(e.target.value); setPage(1); }}><option value=""/>{subjects.map(name => <option key={name}>{name}</option>)}</select></th>
          <th><select aria-label="Filter Faculty Name" value={faculty} onChange={e => { setFaculty(e.target.value); setPage(1); }}><option value=""/>{faculties.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></th><th/><th/></tr></thead>
      <tbody>{loading ? <tr><td colSpan="4" role="status">Loading Lesson Plans Report…</td></tr> : visible.length ? pageRows.map(row => <tr key={row.id}>
        <td>{subjectName(row)}</td><td>{row.faculty_name}</td><td className={Number(row.lesson_count) ? '' : 'lesson-report-nil'}>{Number(row.lesson_count) || 'NIL'}</td>
        <td>{Number(row.lesson_count) > 0 && <button type="button" disabled={downloading !== null} onClick={() => download(row)} aria-label={`Download Lesson Plan for ${subjectName(row)}, ${row.faculty_name}, ${row.academic_year}, ${row.programme_batch}, ${row.semester_name}, ${row.section_name}`} title="Download Lesson Plan">
          {downloading === row.id ? '…' : <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true"><path d="M10 3h4v9h4l-6 6-6-6h4V3ZM3 17h4v3h10v-3h4v6H3v-6Z"/></svg>}
        </button>}</td>
      </tr>) : <tr><td colSpan="4">{error ? 'Lesson Plans Report could not be loaded.' : 'No Lesson Plans match the selected filters.'}</td></tr>}</tbody>
    </table></div>
    {!loading && <div className="lesson-report-pagination">
      <label>Rows per page <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}>{[10, 25, 50, 100].map(size => <option key={size} value={size}>{size}</option>)}</select></label>
      <span role="status">Showing {visible.length ? start + 1 : 0}?{Math.min(start + pageSize, visible.length)} of {visible.length}</span>
      <nav aria-label="Lesson Plans Report pagination">
        <button type="button" disabled={currentPage === 1} onClick={() => setPage(1)}>First</button>
        <button type="button" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous</button>
        <span>Page {currentPage} of {pageCount}</span>
        <button type="button" disabled={currentPage === pageCount} onClick={() => setPage(currentPage + 1)}>Next</button>
        <button type="button" disabled={currentPage === pageCount} onClick={() => setPage(pageCount)}>Last</button>
      </nav>
    </div>}
  </section>;
}
