
rule Trojan_Win32_Hilasy_C{
	meta:
		description = "Trojan:Win32/Hilasy.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c8 83 c4 1c 81 f9 00 10 00 00 0f 86 0d 01 00 00 80 38 4d 0f 85 04 01 00 00 80 78 01 5a } //1
		$a_01_1 = {74 2d 38 5e 04 75 28 8b 46 14 57 8b 7e 18 2b 7e 14 53 8d 4d f8 51 57 50 ff 75 fc ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}