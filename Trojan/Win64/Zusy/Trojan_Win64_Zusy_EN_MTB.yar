
rule Trojan_Win64_Zusy_EN_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 00 61 00 6d 00 65 00 20 00 52 00 65 00 70 00 61 00 63 00 6b 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 Game Repack Install
		$a_01_1 = {8e 39 44 b9 2a 50 47 b8 8e 39 b8 b8 2a 50 47 b8 2b 50 d0 b8 2a 50 47 b8 8e 39 45 b9 2a 50 47 b8 52 69 63 68 2b 50 47 b8 } //1
		$a_01_2 = {2e 74 68 65 6d 69 64 61 00 e0 79 00 00 60 15 00 00 00 00 00 00 b2 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}