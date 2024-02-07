
rule TrojanProxy_Win32_Koobface_gen_B{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 03 1c 00 00 } //01 00 
		$a_03_1 = {6a 02 55 55 6a 1a 68 ff ff 00 00 50 8d 44 24 90 01 01 50 e8 90 01 04 ff d0 90 00 } //01 00 
		$a_01_2 = {c6 45 08 55 c6 45 09 0d } //01 00 
		$a_01_3 = {70 25 73 65 73 25 73 6c 69 63 25 73 } //01 00  p%ses%slic%s
		$a_01_4 = {49 47 59 4d 41 53 } //00 00  IGYMAS
	condition:
		any of ($a_*)
 
}