
rule Trojan_Win32_Dorifel_EALB_MTB{
	meta:
		description = "Trojan:Win32/Dorifel.EALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 10 00 00 00 00 8d 55 e4 89 54 24 0c d1 e0 89 44 24 08 89 74 24 04 89 1c 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}