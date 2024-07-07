
rule TrojanDropper_Win32_Cutwail_AJ{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 4a 43 8b 03 2d 90 01 04 3b c1 75 f4 42 83 fa 90 01 01 75 ee 83 eb 07 80 3b 90 90 74 01 43 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}