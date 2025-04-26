
rule Trojan_Win64_StrelaStealer_ASN_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 21 c8 48 f7 d1 48 21 cd 48 09 c5 48 31 cd } //4
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}