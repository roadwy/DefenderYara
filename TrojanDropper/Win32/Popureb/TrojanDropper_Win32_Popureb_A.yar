
rule TrojanDropper_Win32_Popureb_A{
	meta:
		description = "TrojanDropper:Win32/Popureb.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d2 c8 88 04 46 59 e2 } //1
		$a_01_1 = {81 c1 00 28 00 00 83 d2 00 81 e9 00 02 00 00 83 da 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}