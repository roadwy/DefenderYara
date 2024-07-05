
rule Trojan_Win32_Stealerc_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 83 fe 0a 7c 90 01 01 8b 44 24 90 01 01 8d 4c 24 90 01 01 8a 44 04 90 01 01 30 04 2f e8 90 01 04 8b 54 24 90 01 01 47 3b bc 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}