
rule Trojan_Win32_Katusha_BE_MTB{
	meta:
		description = "Trojan:Win32/Katusha.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 1e f7 1e 31 1e 29 1e 81 06 2d 70 e5 ff 01 1e 83 c6 04 4a 0f 85 } //02 00 
		$a_01_1 = {4d 78 4f 73 54 6a 56 65 58 37 42 32 72 46 31 2e 49 76 6f } //00 00 
	condition:
		any of ($a_*)
 
}