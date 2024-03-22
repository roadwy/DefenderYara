
rule Trojan_Win64_StrelaStealer_ASDF_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {41 57 41 56 41 55 41 54 56 57 55 53 b8 90 01 02 00 00 e8 90 01 03 00 48 29 c4 c7 84 24 90 01 02 00 00 00 00 00 00 81 bc 24 90 01 02 00 00 cc 0c 00 00 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}