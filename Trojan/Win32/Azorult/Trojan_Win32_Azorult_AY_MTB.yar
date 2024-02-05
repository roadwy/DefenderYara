
rule Trojan_Win32_Azorult_AY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 90 90 05 10 01 90 8b 7d fc ff 75 f8 01 3c 24 c3 90 00 } //01 00 
		$a_02_1 = {8b d0 32 8e 90 01 03 00 88 0a 90 05 10 01 90 5e c3 90 0a 30 00 56 90 05 10 01 90 8b f2 90 05 10 01 90 03 c6 90 05 10 01 90 8b d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}