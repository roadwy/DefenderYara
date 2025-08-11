
rule Trojan_Win64_Fragtor_MR_MTB{
	meta:
		description = "Trojan:Win64/Fragtor.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 f0 48 8d 50 01 48 89 55 f0 0f b6 10 48 8b 45 f8 48 8d 48 01 48 89 4d f8 88 10 48 83 6d 20 01 48 83 7d 20 } //10
		$a_01_1 = {89 45 fc 48 8b 45 10 48 8d 50 01 48 89 55 10 0f b6 00 0f b6 c0 89 45 f8 83 7d f8 00 0f 95 c0 84 c0 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}