
rule Trojan_Win64_StrelaStealer_GPAL_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 31 ca 48 21 c2 48 8b 85 ?? 00 00 00 48 89 10 } //4
		$a_03_1 = {49 89 d0 49 31 c8 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 31 ca 4c 09 c0 48 09 ca 48 35 } //4
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1) >=5
 
}