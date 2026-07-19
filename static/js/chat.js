// 채팅 클라이언트
// CSP(script-src 'self')를 유지하기 위해 인라인 스크립트 대신 정적 파일로 분리
(function () {
  var chatEl = document.getElementById('chat');
  if (!chatEl) return;
  var room = chatEl.dataset.room;
  var socket = io();

  socket.on('connect', function () {
    socket.emit('join', { room: room });
  });

  socket.on('message', function (data) {
    var messages = document.getElementById('messages');
    var item = document.createElement('li');
    // textContent 사용 -> 브라우저가 자동으로 이스케이프 처리 (DOM XSS 방지)
    var strong = document.createElement('strong');
    strong.textContent = data.username + ':';
    item.appendChild(strong);
    item.appendChild(document.createTextNode(' ' + data.message));
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
  });

  function sendMessage() {
    var input = document.getElementById('chat_input');
    var message = input.value;
    if (message) {
      socket.emit('send_message', { room: room, message: message });
      input.value = '';
    }
  }

  document.getElementById('chat_send').addEventListener('click', sendMessage);
  document.getElementById('chat_input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') sendMessage();
  });
})();
