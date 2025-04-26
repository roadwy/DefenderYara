
rule TrojanDropper_Win32_Srizbi_gen_E{
	meta:
		description = "TrojanDropper:Win32/Srizbi.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 0f be 11 8b 45 f4 0f be 88 ?? ?? ?? ?? 33 d1 88 55 eb 8b 55 f0 83 c2 01 89 55 f0 8b 45 f4 83 c0 01 25 07 00 00 80 79 05 48 83 c8 f8 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}