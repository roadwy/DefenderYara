
rule Trojan_Win64_Ligooc_GHS_MTB{
	meta:
		description = "Trojan:Win64/Ligooc.GHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c1 48 63 4f 3c 89 87 90 01 04 48 8b 05 90 01 04 44 88 0c 01 ff 47 3c 8b 05 90 01 04 8b 0d 90 01 04 05 90 01 04 2b 8f 90 01 04 03 c8 89 0d 90 01 04 8b 47 7c 35 e8 d1 04 00 29 87 90 01 04 b8 90 01 04 2b 47 5c 01 07 49 81 fa 20 6d 00 00 0f 8c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}