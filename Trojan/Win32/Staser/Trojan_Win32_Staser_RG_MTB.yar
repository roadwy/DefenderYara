
rule Trojan_Win32_Staser_RG_MTB{
	meta:
		description = "Trojan:Win32/Staser.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 0c 01 b8 02 00 00 00 90 e9 } //00 00 
	condition:
		any of ($a_*)
 
}