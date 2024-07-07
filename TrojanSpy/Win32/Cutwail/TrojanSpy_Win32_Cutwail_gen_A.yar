
rule TrojanSpy_Win32_Cutwail_gen_A{
	meta:
		description = "TrojanSpy:Win32/Cutwail.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 84 b7 00 00 00 53 55 8b 2d 90 01 03 13 56 68 90 01 03 13 83 c7 08 57 ff 15 90 01 03 13 85 c0 89 44 24 10 74 7a 80 3f 3c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}