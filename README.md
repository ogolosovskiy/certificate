# certificate

This is simple c++ example how to encrypt / decript something by AES 128.  
Dependences - openssl.  
Windows openssl - https://slproweb.com/products/Win32OpenSSL.html  


Example:  

Create token:  
>cat file1.txt  
  
{08ab7725ceb412cd65386dad279b772eda139472|a2a98ca6|1447417130770}  
>openssl enc -aes-128-cbc -pass pass:34819d7beeabb9260a5c854bc85b3e44D -p -nosalt -in file1.txt -out file1.bin  
key=E170A5D191CF1A84B4314BF9F6ECA428  
iv =079E0AD77D5EE118C401C4BCF51DE4E7  
>openssl enc -base64 -in file1.bin -out file1.base64  
>cat file1.base64  
GVWIkgfNVa//93woCSRK7qLXSJ4Iz14yyoGNhiJHrx8dE8E28Imz40RUd+2H9Mei  
hwC96SN23GYqJf40ybQz0uuN49J4m8MvdneKqGF3Jmw=  
  
Decrypt token:  
>openssl enc -d -base64 -in file1.base64 -out file2.bin  
         warning base64 line length is limited to 64 characters by default in openssl :  
         to be able to decode a base64 line without line feed that exceed 64 characters use -A option :  
>openssl enc -d -aes-128-cbc -pass pass:34819d7beeabb9260a5c854bc85b3e44D -p -nosalt -in file2.bin -out file2.txt  
  
key=E170A5D191CF1A84B4314BF9F6ECA428  
iv =079E0AD77D5EE118C401C4BCF51DE4E7  
>cat file2.txt{08ab7725ceb412cd65386dad279b772eda139472|a2a98ca6|1447417130770}  
  
