
rule Trojan_Win32_Dimnie_C{
	meta:
		description = "Trojan:Win32/Dimnie.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 c7 e3 06 ad e8 } //01 00 
		$a_01_1 = {68 74 c9 ac 4a e8 } //01 00 
		$a_01_2 = {5f 44 4d 4e 42 45 47 5f 31 32 33 34 } //02 00 
		$a_03_3 = {49 6b 7a 5e c7 45 90 01 01 7c 61 6d 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}