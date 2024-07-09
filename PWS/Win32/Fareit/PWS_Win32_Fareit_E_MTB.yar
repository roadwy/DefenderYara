
rule PWS_Win32_Fareit_E_MTB{
	meta:
		description = "PWS:Win32/Fareit.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 33 c2 8b 8d ?? ff ff ff 8b 15 ?? ?? ?? 00 89 04 8a c7 45 fc 06 00 00 00 a1 ?? ?? ?? 00 99 6a 01 59 f7 f9 83 f2 01 89 55 84 c7 85 7c ff ff ff 03 00 00 00 8d 95 7c ff ff ff 8d 4d 9c e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}