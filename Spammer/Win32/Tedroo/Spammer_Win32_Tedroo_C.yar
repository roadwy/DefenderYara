
rule Spammer_Win32_Tedroo_C{
	meta:
		description = "Spammer:Win32/Tedroo.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c3 8b c1 18 cc cc cc cc cc 51 c7 70 c1 09 b8 44 23 40 00 8d 49 00 c9 0b 01 c7 0b c2 0a 22 32 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}