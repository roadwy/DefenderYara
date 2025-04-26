
rule Trojan_Win32_Agent_WTK_MTB{
	meta:
		description = "Trojan:Win32/Agent.WTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 74 6f 70 2d 61 64 77 2e 74 78 74 } //stop-adw.txt  1
		$a_80_1 = {41 64 77 54 65 73 74 2e 65 78 65 } //AdwTest.exe  1
		$a_80_2 = {6d 20 61 20 62 61 64 20 6d 6f 74 68 65 72 20 66 75 63 6b 65 72 } //m a bad mother fucker  1
		$a_80_3 = {4e 6f 62 61 64 79 20 63 61 6e 20 64 69 73 74 72 6f 79 20 6d 65 } //Nobady can distroy me  1
		$a_80_4 = {59 6f 75 20 73 75 63 6b } //You suck  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}