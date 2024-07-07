
rule Spammer_Win32_Tedroo_S{
	meta:
		description = "Spammer:Win32/Tedroo.S,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b e8 85 ed 74 57 53 56 8b 35 08 69 57 6a 30 68 d0 39 55 ff d6 8b 1d 0c f2 f8 85 ff 74 11 8d 44 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}