
rule TrojanDropper_Win32_Omexo_A{
	meta:
		description = "TrojanDropper:Win32/Omexo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 39 50 45 00 00 75 14 8b 95 90 01 04 8b 42 50 50 8b 4d fc 51 ff 15 90 00 } //1
		$a_03_1 = {33 c9 3d 01 00 00 c0 0f 94 c1 89 8d 90 01 04 68 00 80 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}