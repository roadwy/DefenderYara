
rule Trojan_Win32_Copak_CCHS_MTB{
	meta:
		description = "Trojan:Win32/Copak.CCHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 19 81 c0 31 90 01 04 09 ff 81 ef 90 01 04 39 f1 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}