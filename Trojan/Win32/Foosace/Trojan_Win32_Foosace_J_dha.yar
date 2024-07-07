
rule Trojan_Win32_Foosace_J_dha{
	meta:
		description = "Trojan:Win32/Foosace.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {66 69 65 78 00 } //1
		$a_00_1 = {42 73 36 34 00 } //1
		$a_00_2 = {2f 25 73 25 73 25 73 2f 3f 25 73 3d 25 73 } //1 /%s%s%s/?%s=%s
		$a_01_3 = {66 33 55 fc 66 d1 ea 0f b7 d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}