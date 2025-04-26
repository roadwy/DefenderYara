
rule PWS_Win32_Extrew_B{
	meta:
		description = "PWS:Win32/Extrew.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 77 75 3a 80 bd ?? ?? ff ff 6f 75 31 80 bd ?? ?? ff ff 77 75 28 80 bd ?? ?? ff ff 2e 75 1f 80 bd ?? ?? ff ff 65 } //1
		$a_03_1 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? 8b 75 ?? 81 fe 00 00 40 00 72 d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}