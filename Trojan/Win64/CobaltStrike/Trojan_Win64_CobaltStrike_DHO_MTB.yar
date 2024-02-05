
rule Trojan_Win64_CobaltStrike_DHO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 0f b6 44 0f 90 01 01 30 01 48 ff c1 48 83 ea 01 75 90 01 01 49 83 e8 01 75 90 00 } //02 00 
		$a_03_1 = {41 0f b6 0c 00 30 08 48 ff c0 48 83 ea 01 75 90 01 01 49 83 e9 01 75 90 00 } //01 00 
		$a_01_2 = {5c 70 72 6f 6a 65 63 74 73 5c 67 61 72 64 61 5c 73 74 6f 72 61 67 65 5c 74 61 72 67 65 74 73 5c 77 6f 72 6b 36 2e 78 32 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}