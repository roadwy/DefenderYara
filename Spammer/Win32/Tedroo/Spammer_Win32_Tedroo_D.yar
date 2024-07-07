
rule Spammer_Win32_Tedroo_D{
	meta:
		description = "Spammer:Win32/Tedroo.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 00 30 0a 68 90 01 01 21 40 20 01 00 00 80 ff 15 04 20 51 28 39 50 00 50 90 01 01 51 8b 14 24 50 68 72 6a 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}