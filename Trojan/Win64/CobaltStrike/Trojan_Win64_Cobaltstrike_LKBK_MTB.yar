
rule Trojan_Win64_Cobaltstrike_LKBK_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.LKBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 c3 02 c3 e9 } //01 00 
		$a_01_1 = {32 c3 c0 c8 31 e9 } //01 00 
		$a_01_2 = {aa 48 ff c9 e9 } //00 00 
	condition:
		any of ($a_*)
 
}