
rule Trojan_Win32_Redline_ASAV_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 12 ff 74 24 90 01 01 8b cb e8 90 01 02 00 00 8b cb e8 90 01 02 00 00 80 b6 90 00 } //01 00 
		$a_01_1 = {4f 6e 6a 68 72 65 62 79 75 75 58 62 68 6e 41 5a 75 79 74 74 32 76 6a 63 68 6a 73 64 } //00 00  OnjhrebyuuXbhnAZuytt2vjchjsd
	condition:
		any of ($a_*)
 
}