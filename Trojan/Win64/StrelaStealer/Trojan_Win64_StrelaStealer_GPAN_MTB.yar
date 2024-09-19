
rule Trojan_Win64_StrelaStealer_GPAN_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 c2 20 c2 44 30 c0 08 d0 89 c2 } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}