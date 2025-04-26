
rule Trojan_Win64_StrelaStealer_GF_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 01 c8 49 29 c1 41 8a 04 24 41 88 03 44 8b 2d f5 ea 05 00 41 8d 75 ff 41 0f af f5 } //3
		$a_01_1 = {30 c1 f6 c1 01 0f 85 } //2
		$a_01_2 = {89 d0 20 c8 30 d1 08 c1 44 89 c0 30 c8 34 01 20 c8 44 08 c1 34 01 89 c2 30 ca } //4
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1) >=10
 
}