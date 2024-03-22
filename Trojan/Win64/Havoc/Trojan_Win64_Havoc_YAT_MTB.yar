
rule Trojan_Win64_Havoc_YAT_MTB{
	meta:
		description = "Trojan:Win64/Havoc.YAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 4f 60 41 33 cb 01 4f 90 01 01 48 8b 05 90 01 04 8b 08 01 0d 90 01 04 48 63 0d 90 01 04 48 8b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}