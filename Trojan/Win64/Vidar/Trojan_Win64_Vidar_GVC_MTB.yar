
rule Trojan_Win64_Vidar_GVC_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 34 03 48 8b 7c 24 78 48 01 df 0f b6 3f 40 88 3e 48 ff c3 8b 71 54 48 39 f3 72 e3 48 89 44 24 50 48 8d 5c 24 78 48 89 c1 48 8b 44 24 70 e8 22 fb ff ff 48 8b 54 24 50 48 8b 74 24 48 48 39 f2 74 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}