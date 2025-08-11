
rule Trojan_Win32_Farfli_EAG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.EAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0a 32 4d ef 02 4d ef 88 0a 42 89 55 08 c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}