
rule Trojan_Win32_Tofsee_CA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 07 f8 83 d7 90 01 01 f7 d8 83 90 01 02 f8 83 90 01 02 29 c8 6a 90 01 01 59 21 c1 89 02 83 90 01 02 f8 83 90 01 02 85 f6 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}