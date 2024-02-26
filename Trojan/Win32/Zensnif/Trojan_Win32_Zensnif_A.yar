
rule Trojan_Win32_Zensnif_A{
	meta:
		description = "Trojan:Win32/Zensnif.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_43_0 = {45 14 8b 4d 10 8b 55 0c 8b 75 08 90 02 02 8a 24 0a 28 c4 88 90 00 0a } //00 0f 
		$a_66_1 = {00 05 90 01 02 00 00 50 ff 14 24 90 00 00 00 0a 00 5d 04 00 00 81 43 05 80 5c 26 00 00 83 43 05 80 00 00 01 00 08 00 10 00 ac 21 44 65 6c 66 49 6e 6a 65 63 74 2e 50 4f 55 00 00 01 40 05 82 70 00 04 00 } //67 16 
	condition:
		any of ($a_*)
 
}