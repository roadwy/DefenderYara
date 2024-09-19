
rule Trojan_Win64_StrelaStealer_GPAM_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 31 c1 48 09 d0 4c 09 c1 48 35 ff ff ff ff 48 21 c8 48 89 85 } //4
		$a_03_1 = {44 21 d1 45 89 c3 41 83 f3 ff 41 81 e3 ?? ?? ?? ?? 45 21 d0 41 09 c9 45 09 c3 45 31 d9 } //4
		$a_01_2 = {48 31 ca 48 89 c1 48 31 d1 48 21 c1 } //4
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1) >=5
 
}