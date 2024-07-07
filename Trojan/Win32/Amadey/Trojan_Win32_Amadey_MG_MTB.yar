
rule Trojan_Win32_Amadey_MG_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {e0 00 02 01 0b 01 0e 18 00 94 04 00 00 56 07 00 00 00 00 00 ac a3 7a 00 00 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}