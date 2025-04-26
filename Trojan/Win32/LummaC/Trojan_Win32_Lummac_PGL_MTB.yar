
rule Trojan_Win32_Lummac_PGL_MTB{
	meta:
		description = "Trojan:Win32/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 55 fc 89 55 e8 8b 45 fc c1 e0 ?? 33 45 e8 89 45 fc 8b 4d f8 83 c1 ?? 89 4d f8 8b 55 fc c1 ea ?? 03 55 fc 89 55 fc eb b2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}