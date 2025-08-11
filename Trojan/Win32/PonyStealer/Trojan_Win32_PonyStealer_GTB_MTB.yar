
rule Trojan_Win32_PonyStealer_GTB_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 57 00 01 00 08 00 39 48 57 00 01 00 08 } //5 均Āࠀ㤀坈Āࠀ
		$a_01_1 = {31 00 08 37 c8 9b fa a3 96 5f 43 91 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}