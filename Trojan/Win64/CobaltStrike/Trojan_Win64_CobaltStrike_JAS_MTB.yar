
rule Trojan_Win64_CobaltStrike_JAS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 8b d6 33 c9 ff d0 } //1
		$a_01_1 = {b8 3f c5 25 43 41 f7 ea c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 3d 41 8b d2 41 ff c2 2b d0 48 8b 05 67 ae 09 00 4c 63 c2 45 8a 04 00 47 32 04 0e 45 88 01 49 ff c1 48 83 ee 01 75 c5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}