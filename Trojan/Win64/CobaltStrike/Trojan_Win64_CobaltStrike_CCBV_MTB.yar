
rule Trojan_Win64_CobaltStrike_CCBV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 d1 fa 8b c2 c1 e8 90 01 01 03 d0 41 8b c0 41 ff c0 8d 0c 52 c1 e1 90 01 01 2b c1 48 63 c8 42 0f b6 04 19 41 30 42 ff 45 3b c1 7c 90 00 } //1
		$a_01_1 = {5b 2a 5d 20 45 78 65 63 75 74 69 6e 67 } //1 [*] Executing
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}