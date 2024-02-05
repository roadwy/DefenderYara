
rule Trojan_Win64_Emotet_SHN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8d 15 66 90 01 03 48 63 c8 48 8b 05 90 01 04 8a 0c 01 41 32 0c 3e 88 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}