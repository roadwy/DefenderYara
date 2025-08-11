
rule Trojan_Win32_Vidar_AE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 d1 da 59 47 89 46 04 c7 a0 8c 6b 73 94 1b 53 1b 1c 7c 7d d4 52 94 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}