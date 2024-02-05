
rule Trojan_Win32_Apost_G_MTB{
	meta:
		description = "Trojan:Win32/Apost.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 1c 38 eb 90 02 25 80 f3 90 02 25 90 13 90 02 0a 80 f3 90 02 15 90 13 90 02 0a 88 1c 38 90 00 } //01 00 
		$a_02_1 = {a7 8a 1c 38 90 02 10 90 13 80 f3 90 02 15 90 13 f6 d3 90 02 10 90 13 80 f3 90 02 25 90 13 88 1c 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}