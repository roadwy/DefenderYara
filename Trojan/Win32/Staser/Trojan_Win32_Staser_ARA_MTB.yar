
rule Trojan_Win32_Staser_ARA_MTB{
	meta:
		description = "Trojan:Win32/Staser.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 8b 96 90 01 04 8a 14 0a 32 96 90 01 04 41 88 54 01 ff 3b 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}