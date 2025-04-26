
rule Trojan_Win32_Hilasy_A{
	meta:
		description = "Trojan:Win32/Hilasy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 6f 69 61 51 30 72 68 64 } //1 aoiaQ0rhd
		$a_03_1 = {68 70 17 00 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 c3 90 09 07 00 c7 04 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}