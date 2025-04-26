
rule Trojan_Win32_Amadey_MF_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f bf c8 c1 cf 86 66 c1 d1 17 66 33 d0 c1 c8 9d 66 c1 c0 33 66 83 ee 02 47 66 81 eb c7 00 66 c1 ea 57 66 41 66 c1 c2 95 c1 e6 50 66 c1 c2 db f7 ee 66 f7 e7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}