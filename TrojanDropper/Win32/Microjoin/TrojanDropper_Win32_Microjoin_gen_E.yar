
rule TrojanDropper_Win32_Microjoin_gen_E{
	meta:
		description = "TrojanDropper:Win32/Microjoin.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 3d 00 14 40 00 8a c0 8a c0 83 c7 04 89 3d fc 13 40 00 90 8b 35 00 14 40 00 8b 0e 86 ff 86 ff 03 f9 89 3d 04 14 40 00 8a c0 8a c0 68 08 14 40 00 68 00 01 00 00 } //5
		$a_01_1 = {a3 f4 13 40 00 8b 0e 8a c0 8a c0 a1 fc 13 40 00 c0 4c 01 ff 04 e2 f9 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}