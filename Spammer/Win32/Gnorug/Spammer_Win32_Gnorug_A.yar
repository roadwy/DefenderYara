
rule Spammer_Win32_Gnorug_A{
	meta:
		description = "Spammer:Win32/Gnorug.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 f9 77 69 6e 6c 0f 85 cb 00 00 00 8b 4e 04 0b c8 81 f9 6f 67 6f 6e 0f 85 ba 00 00 00 8b 4e 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}