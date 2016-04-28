As super user

./boot
./configure
make
make install


Testing using Mininet - mininet.org

mn --switch user --nat --listen 6634

dpctl add-flow tcp:localhost:6634 dns_dst=www.google.com.br,actions=
or
dpctl add-flow tcp:localost:6634 dns_src=www.google.com.br,actions=

