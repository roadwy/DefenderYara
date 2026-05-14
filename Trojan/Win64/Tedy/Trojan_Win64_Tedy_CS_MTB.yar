
rule Trojan_Win64_Tedy_CS_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 88 14 18 4d 8d 4b ?? 49 39 c9 7d 2f 4d 89 ca 49 83 e1 ?? 4d 89 d3 4d 29 ca 46 0f b6 0c 1a 49 83 fa } //5
		$a_03_1 = {46 0f b6 54 14 ?? 45 31 ca 49 39 cb 72 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}