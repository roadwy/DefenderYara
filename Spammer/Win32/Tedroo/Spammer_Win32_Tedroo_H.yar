
rule Spammer_Win32_Tedroo_H{
	meta:
		description = "Spammer:Win32/Tedroo.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 d6 24 9e 70 30 3e 48 d0 8e b8 38 1d 60 5c 02 55 09 da a6 28 65 6f a4 65 ee 1f 4c 4f 47 47 45 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}