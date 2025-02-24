
rule Trojan_Win32_Banbra_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Banbra.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 8b 45 f8 99 f7 7d f4 89 d0 89 c2 8b 45 10 01 d0 0f b6 00 31 c1 89 ca 8b 45 fc 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}