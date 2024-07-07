
rule Trojan_Win32_Razy_SPDE_MTB{
	meta:
		description = "Trojan:Win32/Razy.SPDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 13 46 81 c3 04 00 00 00 39 cb 75 ee } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}