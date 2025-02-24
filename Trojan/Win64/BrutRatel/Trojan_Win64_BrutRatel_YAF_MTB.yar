
rule Trojan_Win64_BrutRatel_YAF_MTB{
	meta:
		description = "Trojan:Win64/BrutRatel.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f0 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}