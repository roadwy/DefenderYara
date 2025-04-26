
rule Trojan_Win32_Fragtor_SPGG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SPGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 f8 8b 45 f8 33 45 f4 31 45 fc 8b 45 fc 29 45 e8 8b 4d d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}