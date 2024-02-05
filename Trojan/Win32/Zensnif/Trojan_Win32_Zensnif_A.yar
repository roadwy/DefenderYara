
rule Trojan_Win32_Zensnif_A{
	meta:
		description = "Trojan:Win32/Zensnif.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_43_0 = {45 14 8b 4d 10 8b 55 0c 8b 75 08 90 02 02 8a 24 0a 28 c4 88 90 00 0a } //00 0f 
		$a_66_1 = {00 05 90 01 02 00 00 50 ff 14 24 90 00 00 00 0a 00 5d 04 00 00 81 43 05 80 5c 2b 00 00 84 43 05 80 00 00 01 00 08 00 15 00 af 01 44 69 73 61 62 6c 65 44 65 66 65 6e 64 65 72 21 4d 53 52 00 00 01 40 05 } //82 70 
	condition:
		any of ($a_*)
 
}