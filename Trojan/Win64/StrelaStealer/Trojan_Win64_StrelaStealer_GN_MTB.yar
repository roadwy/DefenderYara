
rule Trojan_Win64_StrelaStealer_GN_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 94 c1 30 cb 80 f3 01 89 da 20 ca 30 cb 08 d3 } //2
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}