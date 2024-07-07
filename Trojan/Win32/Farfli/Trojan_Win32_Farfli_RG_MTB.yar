
rule Trojan_Win32_Farfli_RG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 90 90 90 90 8b 55 fc 80 04 11 7a 90 90 90 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}