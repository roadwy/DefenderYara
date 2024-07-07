
rule Trojan_Win32_Adclicker_AI{
	meta:
		description = "Trojan:Win32/Adclicker.AI,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {5c 73 79 73 74 65 6d 33 32 5c 68 6f 6d 65 2e 68 74 6d } //1 \system32\home.htm
		$a_00_1 = {25 73 5c 79 61 68 6f 6f 2e 68 74 6d } //1 %s\yahoo.htm
		$a_00_2 = {25 73 5c 67 6f 6f 67 6c 65 2e 68 74 6d } //1 %s\google.htm
		$a_00_3 = {25 73 5c 6d 73 6e 2e 68 74 6d } //1 %s\msn.htm
		$a_00_4 = {25 73 5c 73 65 63 2e 68 74 6d } //1 %s\sec.htm
		$a_01_5 = {27 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 27 } //1 'Browser Helper Objects'
		$a_01_6 = {42 68 6f 4e 65 77 2e 44 4c 4c } //1 BhoNew.DLL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}