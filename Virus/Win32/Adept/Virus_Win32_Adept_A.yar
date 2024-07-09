
rule Virus_Win32_Adept_A{
	meta:
		description = "Virus:Win32/Adept.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_07_0 = {55 6a 00 83 ec 28 8b ec 60 55 6a 78 68 50 78 2e 61 54 e8 ?? ?? ?? ?? 58 58 5f 8d 77 34 6a 0a 59 f3 a5 61 6a 00 e8 ?? ?? ?? ?? 5d c2 28 00 } //1
	condition:
		((#a_07_0  & 1)*1) >=1
 
}