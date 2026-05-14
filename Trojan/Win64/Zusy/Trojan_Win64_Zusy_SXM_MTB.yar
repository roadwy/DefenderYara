
rule Trojan_Win64_Zusy_SXM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 30 4c 89 64 24 50 4c 8b cf 4c 89 6c 24 58 0f 57 44 24 50 66 0f 7f 44 24 30 44 89 } //10
		$a_01_1 = {c7 44 24 60 02 00 00 00 4c 89 7c 24 58 48 8b 4d 38 48 89 4c 24 50 4c 89 7c 24 48 4c 89 7c 24 40 89 54 24 38 44 89 4c 24 30 44 89 54 24 28 44 89 5c 24 20 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}