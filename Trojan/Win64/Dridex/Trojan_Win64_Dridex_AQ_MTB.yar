
rule Trojan_Win64_Dridex_AQ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AQ!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 89 fa 45 01 ea 45 39 d3 72 02 eb 36 45 89 da 47 8a 14 16 44 88 55 cf 44 0f b6 55 cf 44 8b 4d bc 41 89 f0 45 01 c8 45 0f b6 c8 45 31 ca 44 88 55 cf 45 89 da 44 8a 4d cf 47 88 0c 16 4d 8d 5b 01 } //10
		$a_01_1 = {4c 8b 55 90 4c 01 55 c0 4c 03 65 90 4c 8b 55 a0 4c 03 55 a8 49 83 ea 0a } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}