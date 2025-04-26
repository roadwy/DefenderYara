
rule Trojan_Win32_SourBack_A_dha{
	meta:
		description = "Trojan:Win32/SourBack.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 70 68 6f 73 74 73 76 63 2e 6e 65 74 } //3 uplphostsvc.net
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 76 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows NT\Currentversion
		$a_01_2 = {25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 } //1 %d/%d/%d %d:%d
		$a_01_3 = {2f 49 6e 73 74 61 6c 6c 00 } //1
		$a_01_4 = {80 00 24 40 80 38 00 75 f7 } //1
		$a_01_5 = {04 24 8d 49 01 88 41 ff 8a 01 84 c0 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}