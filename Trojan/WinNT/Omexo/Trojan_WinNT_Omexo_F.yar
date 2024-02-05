
rule Trojan_WinNT_Omexo_F{
	meta:
		description = "Trojan:WinNT/Omexo.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 19 0f b7 47 06 83 45 fc 28 46 3b f0 72 e2 b8 25 02 00 c0 } //01 00 
		$a_01_1 = {53 b8 30 00 df ff 6a 02 8d 50 02 5b 66 8b 08 03 c3 } //01 00 
		$a_01_2 = {bf 03 00 00 f0 eb 05 bf 01 00 00 f0 } //01 00 
		$a_01_3 = {17 00 ca 5a 59 5a 5a 5a } //00 00 
	condition:
		any of ($a_*)
 
}