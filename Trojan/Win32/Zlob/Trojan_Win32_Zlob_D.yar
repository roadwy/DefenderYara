
rule Trojan_Win32_Zlob_D{
	meta:
		description = "Trojan:Win32/Zlob.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 76 01 00 00 68 a4 01 00 00 8b 45 f8 2b 45 f0 2d 76 01 00 00 99 2b c2 d1 f8 50 8b 45 f4 2b 45 ec 2d a4 01 00 00 99 2b c2 d1 f8 50 6a ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}