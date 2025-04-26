
rule Trojan_Win32_Qhost_EM{
	meta:
		description = "Trojan:Win32/Qhost.EM,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 72 69 62 20 2b 25 6a 69 25 20 2b 72 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 25 6a 69 25 6f 73 74 73 } //1 attrib +%ji% +r %windir%\system32\drivers\etc\%ji%osts
		$a_01_1 = {73 65 74 20 6a 69 3d 68 0d 0a 73 65 74 20 7a 69 3d 6e 0d 0a 65 63 25 6a 69 25 6f 20 39 31 2e 31 39 33 2e 31 39 34 2e 31 31 37 20 77 77 77 2e 76 6b 6f 25 7a 69 25 74 61 6b 74 65 2e 72 75 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 25 6a 69 25 6f 73 74 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}