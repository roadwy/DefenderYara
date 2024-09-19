
rule Trojan_Win32_Amadey_RDAC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RDAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d9 31 01 8b 0c 24 81 c4 04 00 00 00 5b 50 89 14 24 53 bb 00 00 00 00 89 da 5b 01 f2 01 1a 5a 56 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}