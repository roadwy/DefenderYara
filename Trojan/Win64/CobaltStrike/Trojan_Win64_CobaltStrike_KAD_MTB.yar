
rule Trojan_Win64_CobaltStrike_KAD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 00 48 8b 4d 90 01 01 48 8b 55 f8 48 01 ca 32 45 90 01 01 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45 90 00 } //1
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 20 64 65 74 65 63 74 65 64 21 20 45 78 69 74 69 6e 67 } //1 Debugging detected! Exiting
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}