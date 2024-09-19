
rule Trojan_Win32_Farfli_ASDH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 40 89 45 08 c7 45 fc 01 00 00 00 b8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}