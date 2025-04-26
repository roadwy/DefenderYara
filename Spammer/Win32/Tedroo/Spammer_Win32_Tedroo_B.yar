
rule Spammer_Win32_Tedroo_B{
	meta:
		description = "Spammer:Win32/Tedroo.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 68 3f 00 0f 00 30 0a 68 44 21 40 20 01 00 00 80 ff 15 0c 20 51 30 39 50 00 50 18 51 8b 14 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}