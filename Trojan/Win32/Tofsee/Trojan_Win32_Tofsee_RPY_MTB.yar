
rule Trojan_Win32_Tofsee_RPY_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 55 f8 8b 4d f4 8d 04 17 31 45 fc 8b fa d3 ef 03 7d dc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}