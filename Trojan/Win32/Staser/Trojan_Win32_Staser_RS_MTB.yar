
rule Trojan_Win32_Staser_RS_MTB{
	meta:
		description = "Trojan:Win32/Staser.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 14 50 e8 fc 44 04 00 85 c0 74 05 e8 6b d7 00 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}