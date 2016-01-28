./configure
make
sudo make install


mn --switch user --nat --listen 6634

dpctl add-flow tcp:localhost:6634 url=www.google.com.br,actions=
