
rule PWS_Win32_Fareit_Delph_AE{
	meta:
		description = "PWS:Win32/Fareit.Delph.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 55 fb 88 10 90 05 05 01 90 8d 45 f4 e8 ?? ?? ff ff 90 05 08 01 90 46 4f 75 90 0a 30 00 8a 16 90 05 05 01 90 80 f2 ?? 88 55 fb } //1
		$a_02_1 = {8b 45 fc 03 45 f8 90 05 07 01 90 8a 13 90 05 04 01 90 80 f2 ?? 90 05 04 01 90 88 10 90 05 07 01 90 8d 45 ?? e8 ?? ?? ff ff 90 05 07 01 90 43 4e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}