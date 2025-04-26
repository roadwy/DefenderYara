
rule Trojan_Win64_Ulise_AP_MTB{
	meta:
		description = "Trojan:Win64/Ulise.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 d2 32 54 04 30 41 32 d0 44 03 c7 41 88 11 4c 03 cf 45 3b c2 7c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}