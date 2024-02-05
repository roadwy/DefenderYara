
rule Trojan_Win64_Emotet_CDL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.CDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 63 d8 48 69 fb 90 01 04 48 89 fe 48 c1 ee 90 01 01 48 c1 ff 90 01 01 01 f7 89 fe c1 e6 90 01 01 01 fe 29 f3 48 63 db 8a 1c 0b 32 1c 02 48 8b 90 02 05 88 1c 02 48 ff c0 48 39 85 88 02 00 00 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}