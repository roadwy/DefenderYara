
rule Trojan_WinNT_Rortiem_A{
	meta:
		description = "Trojan:WinNT/Rortiem.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 31 8b 4d 10 8b 5d 0c 33 ff 8d 51 04 39 02 75 05 80 3b b8 74 0b 47 83 c2 04 83 ff 0f 7c ee eb 90 01 01 8d 04 bd 90 01 04 83 38 00 90 00 } //01 00 
		$a_03_1 = {03 cf 51 8b 4d 08 8b 04 88 03 c7 50 ff 55 0c 85 c0 74 11 8b 45 90 01 01 ff 45 08 8b 4d 08 3b 4e 18 8b 55 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}