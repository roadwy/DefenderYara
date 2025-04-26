
rule Trojan_Win64_FileCoder_NF_MTB{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c8 ff eb 31 48 8b cb e8 a5 00 00 00 48 85 c0 75 05 83 cf ?? eb 0e 48 89 05 b8 1c 05 00 48 89 05 99 1c 05 00 33 c9 e8 5a 32 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_FileCoder_NF_MTB_2{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 41 01 48 83 f8 ?? 7c dc 31 c0 eb 19 48 89 c1 48 c1 e0 ?? 48 8d 15 43 2b 59 00 48 01 c2 } //5
		$a_01_1 = {5a 5a 58 75 4b 37 54 } //1 ZZXuK7T
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}