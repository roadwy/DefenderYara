
rule Trojan_Win64_Zusy_SIC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 6c 24 50 48 89 d6 48 89 cf 48 8d 4d d8 48 89 fa 49 89 f0 e8 2f 37 01 00 0f b6 45 d8 48 8b 4d e8 48 8b 55 f8 44 0f b6 c0 4c 8d 0d ec e2 42 00 } //1
		$a_00_1 = {50 00 61 00 74 00 72 00 69 00 6f 00 74 00 53 00 6f 00 66 00 74 00 } //2 PatriotSoft
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2) >=3
 
}