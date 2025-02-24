
rule Trojan_Win64_Lazy_YAF_MTB{
	meta:
		description = "Trojan:Win64/Lazy.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 17 8b cb 48 33 d1 c1 eb 08 0f b6 ca 49 ff c7 33 5c 8c 40 48 85 ed } //5
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 59 75 77 65 69 20 51 75 73 69 5c 4f 6f 76 69 20 41 70 70 63 } //5 Software\Yuwei Qusi\Oovi Appc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}