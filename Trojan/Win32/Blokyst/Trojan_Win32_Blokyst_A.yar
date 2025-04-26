
rule Trojan_Win32_Blokyst_A{
	meta:
		description = "Trojan:Win32/Blokyst.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 46 61 73 74 4c 6f 61 64 65 72 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 75 73 70 73 2e 70 64 62 } //1 \FastLoader\ConsoleApp1\obj\Debug\usps.pdb
		$a_00_1 = {4f 00 6e 00 6b 00 79 00 6f 00 62 00 6c 00 61 00 73 00 74 00 65 00 72 00 4f 00 53 00 20 00 58 00 2d 00 66 00 35 00 2e 00 39 00 39 00 } //1 OnkyoblasterOS X-f5.99
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}