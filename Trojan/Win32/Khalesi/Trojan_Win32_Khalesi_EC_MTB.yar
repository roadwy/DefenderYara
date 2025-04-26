
rule Trojan_Win32_Khalesi_EC_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {df 42 ea 31 38 81 c0 04 00 00 00 39 d0 75 ef 41 01 de c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}