
rule Trojan_Win64_Fabookie_NF_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 a4 0a 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 10 eb 06 48 63 c3 } //5
		$a_01_1 = {4a 30 73 78 4a 38 } //1 J0sxJ8
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_Fabookie_NF_MTB_2{
	meta:
		description = "Trojan:Win64/Fabookie.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 03 01 00 00 33 db eb 2b 44 8b 48 ?? 33 c0 8d 58 ?? 84 c9 75 22 46 3b 8c 00 ?? ?? ?? ?? 75 0a 42 8b } //5
		$a_03_1 = {eb 3b 33 c0 48 8b cf 41 8d 51 ?? e8 6e 2b 00 00 4c 8b 1f 48 8d 54 24 ?? 48 8b cf 41 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}