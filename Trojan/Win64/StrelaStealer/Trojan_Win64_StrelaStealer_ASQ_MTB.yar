
rule Trojan_Win64_StrelaStealer_ASQ_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 20 41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 } //2
		$a_01_1 = {48 83 c4 20 48 89 45 } //2
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}