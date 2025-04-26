
rule Trojan_Win32_Fragtor_LS_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed ec c2 39 00 e9 04 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}