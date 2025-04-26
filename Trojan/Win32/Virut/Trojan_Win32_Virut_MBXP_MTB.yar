
rule Trojan_Win32_Virut_MBXP_MTB{
	meta:
		description = "Trojan:Win32/Virut.MBXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c 51 41 00 06 f9 36 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 [0-06] 4f 41 00 fc 17 40 00 78 00 00 00 80 00 00 00 85 00 00 00 86 [0-19] 57 49 4e 44 4f 57 53 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}