
rule Trojan_Win32_Fakemsn_I{
	meta:
		description = "Trojan:Win32/Fakemsn.I,SIGNATURE_TYPE_PEHSTR,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 73 6e 20 48 61 63 6b 65 72 } //1 Msn Hacker
		$a_01_1 = {5c 77 69 6e 64 6f 77 73 20 4c 69 76 65 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6e 31 2e 65 78 65 } //1 \windows Live\Messenger\msn1.exe
		$a_01_2 = {77 77 77 2e 69 6e 76 61 73 61 6f 68 61 63 6b 69 6e 67 2e 63 6f 6d } //3 www.invasaohacking.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=4
 
}