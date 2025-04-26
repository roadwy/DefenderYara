
rule Trojan_Win64_BumbleBee_AB{
	meta:
		description = "Trojan:Win64/BumbleBee.AB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 83 ec 38 31 d2 48 89 4c 24 30 48 8b 4c 24 30 48 89 c8 48 83 c0 10 48 89 4c 24 28 48 89 c1 41 b8 08 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 28 c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10 48 83 c4 38 c3 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*5) >=6
 
}