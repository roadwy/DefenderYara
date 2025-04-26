
rule Trojan_Win64_Emotet_RDD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 ff c3 48 8b 44 24 40 0f b6 8c 31 ?? ?? ?? ?? 32 0c 02 48 8b 44 24 38 88 0c 02 48 ff c2 48 63 c3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}