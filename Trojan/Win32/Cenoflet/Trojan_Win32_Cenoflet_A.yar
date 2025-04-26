
rule Trojan_Win32_Cenoflet_A{
	meta:
		description = "Trojan:Win32/Cenoflet.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 2f 6c 6f 77 20 2f 6d 69 6e 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 22 68 74 74 70 3a 2f 2f 73 68 6f 63 6b 77 61 76 65 66 6c 61 73 68 75 70 2e 73 79 74 65 73 2e 6e 65 74 2f 73 75 63 63 65 73 73 66 75 6c 2e } //1 start /low /min iexplore.exe "http://shockwaveflashup.sytes.net/successful.
		$a_01_1 = {25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 70 69 6e 67 2e 65 78 65 20 79 63 2e 73 68 6f 63 6b 77 61 76 65 73 66 78 2e 63 6f 6d 20 2d 6e 20 31 20 2d 6c 20 31 } //1 %windir%\system32\ping.exe yc.shockwavesfx.com -n 1 -l 1
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 6f 6b 25 2f 70 72 6f 78 79 2e 70 61 63 } //1 http://%ok%/proxy.pac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}