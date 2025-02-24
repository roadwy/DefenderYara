
rule Trojan_Win64_BruteRatel_BSA_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 c1 fa 02 4d 85 d2 74 32 4c 8b c7 66 66 66 0f 1f 84 00 00 00 00 00 41 8b 08 8b c1 0f af c1 3b c3 7f 18 8b c3 99 f7 f9 85 d2 74 3e 41 ff c1 49 83 c0 04 49 63 c1 49 3b c2 72 dc 4c 3b de 74 0d 41 89 1b } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}