
rule Trojan_Win32_Zlob_A{
	meta:
		description = "Trojan:Win32/Zlob.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 2b 44 24 08 6a 00 2d 76 01 00 00 99 2b c2 68 76 01 00 00 d1 f8 68 a4 01 00 00 50 8b 44 24 1c 2b 44 24 14 2d a4 01 00 00 99 2b c2 d1 f8 50 6a ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}