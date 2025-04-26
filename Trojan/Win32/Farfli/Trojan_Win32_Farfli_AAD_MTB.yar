
rule Trojan_Win32_Farfli_AAD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 3a 34 30 2c 49 88 04 3a 42 3b d3 7c f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}