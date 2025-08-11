
rule Trojan_Win64_Strab_GZK_MTB{
	meta:
		description = "Trojan:Win64/Strab.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {b2 30 1b 36 e4 bc 33 12 00 ab ?? ?? ?? ?? c6 f8 c1 fe 33 b6 ?? ?? ?? ?? f2 00 ee } //5
		$a_01_1 = {2e 74 68 65 6d 69 64 61 00 e0 2e 00 00 10 16 00 00 00 00 00 00 40 14 00 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 e0 2e 62 6f 6f 74 00 00 00 00 dc 1c 00 00 f0 44 00 00 dc 1c 00 00 40 14 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}