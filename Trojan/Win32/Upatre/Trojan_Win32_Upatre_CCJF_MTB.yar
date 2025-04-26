
rule Trojan_Win32_Upatre_CCJF_MTB{
	meta:
		description = "Trojan:Win32/Upatre.CCJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 2b 13 f7 da 8d 5b 04 f7 d2 8d 52 f0 c1 ca 02 c1 ca 06 31 fa 83 c2 ff 52 5f c1 c7 02 c1 c7 06 89 11 83 c1 04 8d 76 fc 85 f6 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}