
rule Trojan_Win32_Emotet_DBT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 14 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 8a 18 8a 54 14 90 01 01 32 da 88 18 40 89 44 24 90 01 01 ff 4c 24 90 01 01 0f 90 00 } //14 00 
		$a_02_1 = {03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8b 84 24 90 01 04 8a 54 14 90 01 01 32 da 88 5d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}