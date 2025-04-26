
rule Trojan_Win32_Copak_CRTD_MTB{
	meta:
		description = "Trojan:Win32/Copak.CRTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 31 0a 29 c7 09 f8 42 39 f2 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}