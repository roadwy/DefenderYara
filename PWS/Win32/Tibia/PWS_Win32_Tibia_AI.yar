
rule PWS_Win32_Tibia_AI{
	meta:
		description = "PWS:Win32/Tibia.AI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 54 1f ff 03 d3 f7 d2 88 54 18 ff 43 4e 75 e7 } //1
		$a_01_1 = {8b d8 6b c6 54 03 d8 8b d7 8d 03 e8 } //1
		$a_01_2 = {26 70 61 73 73 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}