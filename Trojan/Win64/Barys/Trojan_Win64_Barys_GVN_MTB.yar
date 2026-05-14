
rule Trojan_Win64_Barys_GVN_MTB{
	meta:
		description = "Trojan:Win64/Barys.GVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {48 63 c1 4c 8d 44 24 20 4c 03 c0 b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 33 0f b6 c1 ff c1 2a c2 04 30 41 30 00 83 f9 0d 7c cb } //1
		$a_01_1 = {4c 8d 35 c8 ce 18 00 4c 89 74 24 50 48 8d 05 cc ce 18 00 48 89 44 24 58 48 8d 05 d0 ce 18 00 48 89 44 24 60 48 8d 05 d4 ce 18 00 48 89 44 24 68 48 8d 05 d8 ce 18 00 48 89 44 24 70 48 8d 05 dc ce 18 00 48 89 44 24 78 48 8d 05 e0 ce 18 00 48 89 45 80 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}