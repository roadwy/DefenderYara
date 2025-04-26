
rule Trojan_Win32_Pirminay_B{
	meta:
		description = "Trojan:Win32/Pirminay.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 6d 00 61 00 64 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Smad.Properties.Resources
		$a_01_1 = {41 64 53 65 72 76 65 72 00 72 75 6e 41 64 } //1 摁敓癲牥爀湵摁
		$a_00_2 = {5c 53 61 6e 63 74 69 6f 6e 65 64 4d 65 64 69 61 5c 53 6d 61 64 } //1 \SanctionedMedia\Smad
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}