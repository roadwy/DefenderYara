
rule Trojan_Win64_StrelaStealer_A_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d0 35 e9 60 ea ?? 81 f2 16 9f 05 61 41 89 c9 41 81 e1 10 9d 10 6f 41 81 e2 ef 62 ef ?? 45 09 ca 09 d1 81 e2 10 9d 10 6f 25 ef 62 ef ?? 09 d0 44 31 d0 } //2
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}