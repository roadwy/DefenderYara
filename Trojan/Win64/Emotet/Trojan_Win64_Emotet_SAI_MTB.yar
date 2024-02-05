
rule Trojan_Win64_Emotet_SAI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 d8 48 90 01 06 48 90 01 02 48 90 01 03 48 90 01 03 01 f7 6b ff 90 01 01 29 fb 48 90 01 02 8a 1c 0b 32 1c 02 48 90 01 06 88 1c 02 48 90 01 02 48 90 01 06 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}