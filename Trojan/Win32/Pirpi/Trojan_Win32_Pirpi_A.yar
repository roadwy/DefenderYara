
rule Trojan_Win32_Pirpi_A{
	meta:
		description = "Trojan:Win32/Pirpi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2 } //1
		$a_03_1 = {74 2a 68 01 00 00 7f e8 ?? ?? ?? ?? 39 85 ?? ?? ?? ?? 74 18 81 bd ?? ?? ?? ?? bd 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}