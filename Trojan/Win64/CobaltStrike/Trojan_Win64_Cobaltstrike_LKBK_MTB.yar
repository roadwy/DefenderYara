
rule Trojan_Win64_Cobaltstrike_LKBK_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.LKBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 c3 02 c3 e9 } //1
		$a_01_1 = {32 c3 c0 c8 31 e9 } //1
		$a_01_2 = {aa 48 ff c9 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}