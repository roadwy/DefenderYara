
rule Trojan_Win64_Bobik_CM_MTB{
	meta:
		description = "Trojan:Win64/Bobik.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 45 a8 0f 57 45 a0 48 89 b4 24 a0 00 00 00 66 0f 7f 45 c0 4c 89 b4 24 b0 } //2
		$a_03_1 = {33 c9 89 4c 24 20 0f 57 c0 0f 11 03 48 89 0b 48 89 4b 08 48 89 4b 10 c7 44 24 20 01 00 00 00 41 b8 00 de 17 00 48 8d 15 ?? ?? ?? ?? 48 8b cb e8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}