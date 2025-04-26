
rule Trojan_Win32_Tofsee_EAOO_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 44 24 14 be 08 9a 76 8b 44 24 60 8b 4c 24 14 8b 54 24 10 8b f8 d3 e7 8b f0 c1 ee 05 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}