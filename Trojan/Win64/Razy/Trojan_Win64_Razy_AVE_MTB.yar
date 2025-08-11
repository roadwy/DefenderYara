
rule Trojan_Win64_Razy_AVE_MTB{
	meta:
		description = "Trojan:Win64/Razy.AVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 01 41 8b 08 8b 14 86 49 03 cb 33 c0 8a 19 49 03 d3 84 db 74 24 c1 c0 03 48 ff c1 89 44 24 10 30 5c 24 10 8a 19 84 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}