
rule Trojan_Win64_Latrodectus_DH_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 5c 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 d3 47 0a 00 0f 86 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}