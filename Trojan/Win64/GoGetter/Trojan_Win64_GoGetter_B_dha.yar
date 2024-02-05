
rule Trojan_Win64_GoGetter_B_dha{
	meta:
		description = "Trojan:Win64/GoGetter.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 0a 00 "
		
	strings :
		$a_43_0 = {1f 40 00 48 39 cb 75 11 48 89 c3 48 90 01 04 e8 90 01 04 84 c0 75 9e 90 00 0a } //00 0f 
		$a_03_1 = {75 0d 66 81 38 65 6e 75 06 80 78 02 64 74 5a 00 17 43 c6 44 24 1f 03 48 8b 94 24 90 01 01 01 00 00 48 8b 90 01 01 ff 90 00 00 00 5d 04 00 00 94 13 05 80 5c 31 00 00 95 13 05 80 00 00 01 00 08 00 } //1b 00 
	condition:
		any of ($a_*)
 
}