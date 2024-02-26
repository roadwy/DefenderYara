
rule Trojan_Win32_Farfli_VR_MTB{
	meta:
		description = "Trojan:Win32/Farfli.VR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 52 01 3a c3 8c cc 83 c1 05 } //01 00 
		$a_01_1 = {38 a7 8b 4e 24 c3 26 2c 8b 41 0c c3 22 8d 50 ff c3 4c 89 51 0c } //00 00 
	condition:
		any of ($a_*)
 
}