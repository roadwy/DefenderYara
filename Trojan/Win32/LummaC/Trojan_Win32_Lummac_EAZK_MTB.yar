
rule Trojan_Win32_Lummac_EAZK_MTB{
	meta:
		description = "Trojan:Win32/Lummac.EAZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 45 fc 89 45 e8 8b 4d fc c1 e1 10 33 4d e8 89 4d fc 8b 55 f8 83 c2 04 89 55 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}