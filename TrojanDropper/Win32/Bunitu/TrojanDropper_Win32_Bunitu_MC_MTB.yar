
rule TrojanDropper_Win32_Bunitu_MC_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c6 2b c8 8b f1 c1 e6 90 01 01 03 75 90 01 01 8b c1 c1 e8 90 01 01 03 45 90 01 01 03 d9 33 f3 33 f0 c7 05 90 02 08 89 45 90 01 01 2b d6 8b 45 90 01 01 29 45 90 01 01 83 ef 90 01 01 75 90 01 01 8b 45 90 01 01 5f 5e 89 10 89 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}