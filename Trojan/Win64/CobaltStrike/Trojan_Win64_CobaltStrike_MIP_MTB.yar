
rule Trojan_Win64_CobaltStrike_MIP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 04 4d 41 30 4c 06 fd 0f b6 4c 04 4e 41 30 4c 06 fe 0f b6 4c 04 4f 41 30 4c 06 ff 0f b6 4c 04 50 41 30 0c 06 48 83 c0 10 48 83 f8 7f 0f 85 53 ff ff ff } //1
		$a_01_1 = {32 44 24 44 43 88 44 2e 0c 0f b6 44 24 2d 32 44 24 45 43 88 44 2e 0d 0f b6 44 24 2e 32 44 24 46 43 88 44 2e 0e 0f b6 44 24 2f 32 44 24 47 43 88 44 2e 0f 0f 29 44 24 20 48 8b 05 88 c3 02 00 0f b6 00 3c 01 0f 85 a5 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}