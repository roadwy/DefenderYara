
rule TrojanDropper_Win32_Tracur_gen_E{
	meta:
		description = "TrojanDropper:Win32/Tracur.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 7d 08 b9 ?? ?? 00 00 31 c8 d3 0f 90 04 01 02 28 29 07 d3 0f 83 ef 04 e2 f3 90 09 0a 00 bf ?? 90 04 01 02 1b 3b 00 00 b8 } //1
		$a_03_1 = {03 7d 08 b9 ?? ?? 00 00 31 c8 d3 0f 28 07 d3 0f 83 ef 04 49 75 f2 90 09 0a 00 bf ?? 1b 00 00 b8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}