
rule Trojan_Win32_Ramnit_gen_B{
	meta:
		description = "Trojan:Win32/Ramnit.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 70 1c 90 90 8f 45 f8 90 90 90 90 90 90 90 ff 70 38 90 90 8f 45 f4 90 90 90 90 90 90 8b 45 fc 05 00 00 01 00 } //01 00 
		$a_01_1 = {73 13 80 3f 0d 75 0e 80 7f 01 0a 75 08 80 3e 0a 75 03 47 eb 19 } //01 00 
		$a_01_2 = {40 90 90 c6 00 5c 40 90 90 c6 00 00 90 90 33 c0 90 90 89 85 f4 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}