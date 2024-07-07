
rule Trojan_Win32_Lazy_HNA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 95 c0 89 45 e4 90 09 70 00 90 02 15 00 11 00 00 90 02 05 00 04 00 01 90 02 1f 0a 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}