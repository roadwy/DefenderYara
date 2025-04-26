
rule Trojan_Win64_CobaltStrike_DWE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 10 48 8d 40 01 80 e9 2d 88 48 ff 48 83 eb 01 75 ec } //1
		$a_01_1 = {41 0f b6 04 3a 41 8d 49 01 42 32 04 02 45 33 c9 88 07 48 8d 7f 01 83 f9 25 48 8d 42 01 44 0f 4e c9 33 d2 83 f9 25 48 0f 4e d0 49 83 eb 01 75 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}