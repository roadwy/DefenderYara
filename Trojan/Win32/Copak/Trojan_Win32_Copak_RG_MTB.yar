
rule Trojan_Win32_Copak_RG_MTB{
	meta:
		description = "Trojan:Win32/Copak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 19 50 8b 04 24 83 c4 04 41 39 f9 75 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}