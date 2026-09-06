import { useEffect, useRef, useState } from 'react';
import './AttendanceEntryReport.css';

const columns=[['attendance_date','Date'],['update','Update Date'],['start_time','Start Time'],['end_time','End Time'],['programme_code','Course'],['batch_name','Batch'],['section_name','Section'],['semester_name','Semester'],['topic_covered','Topic Covered'],['subject','Subject'],['subject_type','Subject Type'],['student_group','Group'],['faculty_name','Faculty'],['strength','Strength'],['present_count','Present'],['absent_count','Absent']];
const dropdowns=new Set(['programme_code','batch_name','semester_name','subject','subject_type','student_group','faculty_name']);
const dateText=value=>String(value||'').slice(0,10).split('-').reverse().join('-');
const timeText=value=>{const [h,m]=String(value||'').split(':');return h?`${String(Number(h)%12||12).padStart(2,'0')}:${m} ${Number(h)<12?'AM':'PM'}`:'';};
async function request(url,options={}){const response=await fetch(url,{...options,headers:{'Content-Type':'application/json',Authorization:`Bearer ${localStorage.getItem('abit_session')}`}});const body=await response.json();if(!response.ok)throw new Error(body.message||'Unable to complete request.');return body;}
export default function AttendanceEntryReport(){
  const [entries,setEntries]=useState([]),[loading,setLoading]=useState(true),[error,setError]=useState(''),[message,setMessage]=useState(''),[range,setRange]=useState({from:'',to:''}),[applied,setApplied]=useState({from:'',to:''}),[filters,setFilters]=useState({}),[editing,setEditing]=useState(null),[date,setDate]=useState(''),[saving,setSaving]=useState(false),[modalError,setModalError]=useState('');
  const [page,setPage]=useState(1),[pageSize,setPageSize]=useState(10);
  const dialog=useRef(null),trigger=useRef(null);
  useEffect(()=>{let active=true;request('/api/student-attendance').then(body=>{if(active)setEntries(body.entries||[]);}).catch(err=>{if(active)setError(err.message);}).finally(()=>{if(active)setLoading(false);});return()=>{active=false;};},[]);
  useEffect(()=>{if(editing){dialog.current.showModal();dialog.current.querySelector('header button')?.focus();}else trigger.current?.focus();},[editing]);
  const value=(row,key)=>key==='subject'?`${row.subject_code}: ${row.subject_name}`:key==='attendance_date'?dateText(row[key]):key.endsWith('_time')?timeText(row[key]):String(row[key]??'');
  const visible=entries.filter(row=>{const day=String(row.attendance_date).slice(0,10);return (!applied.from||day>=applied.from)&&(!applied.to||day<=applied.to)&&Object.entries(filters).every(([key,filter])=>!filter||(key==='attendance_date'?day===filter:dropdowns.has(key)?value(row,key)===filter:value(row,key).toLowerCase().includes(filter.toLowerCase())));});
  const pageCount=Math.max(1,Math.ceil(visible.length/pageSize));
  const currentPage=Math.min(page,pageCount);
  const start=(currentPage-1)*pageSize;
  const pageRows=visible.slice(start,start+pageSize);
  const close=()=>{if(saving)return;dialog.current.close();setEditing(null);setModalError('');};
  const save=async event=>{event.preventDefault();setSaving(true);setModalError('');try{const body=await request(`/api/student-attendance/${editing.id}/date`,{method:'PATCH',body:JSON.stringify({date})});setEntries(rows=>rows.map(row=>row.id===editing.id?{...row,attendance_date:body.date}:row));setMessage('Attendance date updated successfully.');dialog.current.close();setEditing(null);}catch(err){setModalError(err.message);}finally{setSaving(false);}};
  return <div className="entry-report">
    <form className="entry-report-range" onSubmit={event=>{event.preventDefault();if(range.from&&range.to&&range.from>range.to){setError('From Date must be on or before To Date.');return;}setError('');setApplied({...range});setPage(1);}}><label>From Date<input type="date" value={range.from} onChange={e=>setRange({...range,from:e.target.value})}/></label><label>To Date<input type="date" value={range.to} onChange={e=>setRange({...range,to:e.target.value})}/></label><button className="entry-search">Search</button><button type="button" onClick={()=>{setRange({from:'',to:''});setApplied({from:'',to:''});setFilters({});setPage(1);setError('');setMessage('');}}>Reset</button></form>
    {error&&<p role="alert" className="entry-error">{error}</p>}{message&&<p role="status">{message}</p>}
    <section><div className="entry-table-scroll"><table><thead><tr>{columns.map(([key,label])=><th key={key}>{label}</th>)}</tr><tr>{columns.map(([key,label])=><th key={key}>{!['update','strength','present_count','absent_count'].includes(key)&&(dropdowns.has(key)?<select aria-label={`Filter ${label}`} value={filters[key]||''} onChange={e=>{setFilters({...filters,[key]:e.target.value});setPage(1);}}><option value=""/>{[...new Set(entries.map(row=>value(row,key)))].filter(Boolean).sort().map(item=><option key={item}>{item}</option>)}</select>:<input type={key==='attendance_date'?'date':'text'} aria-label={`Filter ${label}`} value={filters[key]||''} onChange={e=>{setFilters({...filters,[key]:e.target.value});setPage(1);}}/>)}</th>)}</tr></thead><tbody>{loading?<tr><td colSpan={16}>Loading attendance entries…</td></tr>:visible.length?pageRows.map(row=><tr key={row.id}>{columns.map(([key])=><td key={key}>{key==='update'?<button className="entry-date-button" aria-label={`Update attendance date for ${row.subject_name} on ${dateText(row.attendance_date)}`} onClick={e=>{trigger.current=e.currentTarget;setDate(String(row.attendance_date).slice(0,10));setModalError('');setEditing(row);}}><svg viewBox="0 0 64 64" width="28" height="28" aria-hidden="true"><rect x="1" y="7" width="62" height="56" rx="10" fill="#ed0000"/><rect x="5" y="20" width="54" height="39" rx="6" fill="#fff"/><g fill="#999" stroke="#666" strokeWidth=".7">{[14,25,36,47].map(x=><rect key={x} x={x-2} y="2" width="5" height="12" rx="2.5"/>)}</g><g fill="#736e6e">{[25,36,47].flatMap(y=>[13,28,43].map(x=><rect key={`${x}-${y}`} x={x} y={y} width="10" height="8" rx=".5" fill={x===43&&y===36?"#e00000":undefined}/>))}</g></svg></button>:value(row,key)}</td>)}</tr>):<tr><td colSpan={16}>No attendance entries found.</td></tr>}</tbody></table></div>
      {!loading&&<div className="entry-report-pagination">
        <label>Rows per page <select value={pageSize} onChange={e=>{setPageSize(Number(e.target.value));setPage(1);}}>{[10,25,50,100].map(size=><option key={size} value={size}>{size}</option>)}</select></label>
        <span role="status">Showing {visible.length?start+1:0} to {Math.min(start+pageSize,visible.length)} of {visible.length}</span>
        <nav aria-label="Attendance Entry Report pagination">
          <button type="button" disabled={currentPage===1} onClick={()=>setPage(1)}>First</button>
          <button type="button" disabled={currentPage===1} onClick={()=>setPage(currentPage-1)}>Previous</button>
          <span>Page {currentPage} of {pageCount}</span>
          <button type="button" disabled={currentPage===pageCount} onClick={()=>setPage(currentPage+1)}>Next</button>
          <button type="button" disabled={currentPage===pageCount} onClick={()=>setPage(pageCount)}>Last</button>
        </nav>
      </div>}
    </section>
    <dialog ref={dialog} className="entry-date-dialog" aria-labelledby="entry-date-title" onCancel={event=>{event.preventDefault();close();}}><header><h2 id="entry-date-title">Update Attendance Date</h2><button aria-label="Close" disabled={saving} onClick={close}>×</button></header><form onSubmit={save}><label><span>Attendance Date</span><input type="date" required value={date} onChange={e=>setDate(e.target.value)}/></label>{modalError&&<p role="alert" className="entry-error">{modalError}</p>}<div><button className="entry-update" disabled={saving}>{saving?'Updating…':'Update'}</button><button type="button" disabled={saving} onClick={()=>{setDate(String(editing.attendance_date).slice(0,10));setModalError('');}}>Reset</button><button type="button" className="entry-dialog-close" disabled={saving} onClick={close}>Close</button></div></form></dialog>
  </div>;
}
