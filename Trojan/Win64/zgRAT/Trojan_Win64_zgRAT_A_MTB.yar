
rule Trojan_Win64_zgRAT_A_MTB{
	meta:
		description = "Trojan:Win64/zgRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 00 83 f8 ff 74 90 01 01 a8 10 75 90 01 01 48 8d 0d 90 01 03 00 ff 15 90 01 02 02 00 83 f8 ff 74 90 01 01 a8 10 75 90 01 01 48 8d 0d 90 01 03 00 ff 15 90 01 02 02 00 83 f8 ff 0f 84 90 01 02 00 00 a8 10 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}