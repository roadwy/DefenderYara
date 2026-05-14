
rule Trojan_Win64_Midie_GTV_MTB{
	meta:
		description = "Trojan:Win64/Midie.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 24 49 03 cb 42 0f b7 14 51 8b 4e 1c 49 03 cb 8b 04 91 48 8d 4d e0 49 03 c3 ff d0 } //5
		$a_01_1 = {48 89 45 10 48 8b 45 10 48 89 45 d0 48 89 7d 10 48 8b 45 10 48 89 45 d8 48 89 5d 10 48 8b 45 10 48 89 7d 10 48 89 45 f0 48 8b 45 10 66 0f 6f 45 d0 48 89 45 f8 0f 57 45 f0 48 8d 55 e0 48 8d 4d d0 66 0f 7f 45 d0 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}