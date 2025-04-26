
rule Trojan_Win64_Dacic_AMAK_MTB{
	meta:
		description = "Trojan:Win64/Dacic.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b0 01 48 83 c4 38 c3 cc cc cc cc 80 79 05 00 74 1d 33 c0 0f 1f 84 00 00 00 00 00 8d 50 eb 30 14 01 48 ff c0 48 83 f8 04 72 f1 c6 41 05 00 48 8b c1 c3 } //1
		$a_03_1 = {74 20 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 8d 48 eb 30 0c 02 48 ff c0 48 83 f8 07 72 f1 c6 42 08 00 4c 8d 42 07 48 8b cb 4c 8d 4c 24 48 e8 ?? ?? ?? ?? 48 8b c3 48 83 c4 30 5b c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}