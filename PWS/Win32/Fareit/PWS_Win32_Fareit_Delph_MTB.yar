
rule PWS_Win32_Fareit_Delph_MTB{
	meta:
		description = "PWS:Win32/Fareit.Delph!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 55 f7 88 10 90 05 05 01 90 8d 45 f8 e8 ?? ?? ff ff 90 0a 30 00 8a 16 90 05 05 01 90 80 f2 ?? 88 55 f7 90 05 05 01 90 8a 55 f7 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}