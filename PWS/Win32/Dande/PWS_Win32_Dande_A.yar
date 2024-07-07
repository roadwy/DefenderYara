
rule PWS_Win32_Dande_A{
	meta:
		description = "PWS:Win32/Dande.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {60 64 8b 05 18 00 00 00 8b 40 30 0f b6 40 02 89 45 fc 61 a1 90 01 04 83 38 02 74 05 33 c0 89 45 fc 90 00 } //1
		$a_03_1 = {8b 95 f8 fd ff ff b8 90 01 04 e8 90 01 04 85 c0 7e 07 8b 45 0c 89 30 33 db 33 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}