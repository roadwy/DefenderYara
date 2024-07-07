
rule Trojan_Win32_Copak_AMAA_MTB{
	meta:
		description = "Trojan:Win32/Copak.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3e 81 eb 01 00 00 00 89 da 81 eb 90 01 04 81 e7 ff 00 00 00 21 d1 09 ca 31 38 81 eb 90 01 04 f7 d2 40 09 d3 01 d1 09 d2 46 89 d9 81 c2 90 01 04 29 d3 81 f8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}