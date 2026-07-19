// data-confirm 속성이 있는 폼 제출 시 확인 대화상자 표시
// CSP(script-src 'self')가 인라인 onsubmit 핸들러를 차단하므로 정적 파일에서 이벤트 바인딩
document.addEventListener('submit', function (e) {
  var form = e.target;
  if (form.dataset && form.dataset.confirm) {
    if (!window.confirm(form.dataset.confirm)) {
      e.preventDefault();
    }
  }
});
