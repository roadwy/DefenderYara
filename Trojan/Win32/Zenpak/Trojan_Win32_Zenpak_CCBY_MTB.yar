
rule Trojan_Win32_Zenpak_CCBY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 de 81 c6 90 01 04 0f b7 36 31 fe 01 ce 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}