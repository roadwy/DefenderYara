
rule Trojan_Win32_Farfli_RPX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 c9 01 ff 8d 14 02 8b 12 81 e2 ff 00 00 00 81 c0 01 00 00 00 09 f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 33 81 ea 01 00 00 00 bf 90 01 04 43 29 ff 4f 39 c3 75 d5 01 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d ff 81 e1 ff 00 00 00 8b 55 fe 81 e2 ff 00 00 00 0b ca 85 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d8 89 5c 24 50 85 db 74 78 33 c0 80 34 30 63 40 3d 8c 03 00 00 72 f4 8d 44 24 14 50 6a 00 6a 00 56 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 53 53 6a 00 6a 00 ff 15 90 01 04 8b f0 5f 85 f6 75 04 5e 5b 59 c3 90 00 } //01 00 
		$a_01_1 = {68 64 69 65 74 72 69 63 68 32 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //00 00  hdietrich2@hotmail.com
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 2c 4b c6 44 24 2e 52 c6 44 24 2f 4e c6 44 24 31 4c c6 44 24 32 33 c6 44 24 33 32 c6 44 24 34 2e c6 44 24 35 64 c6 44 24 38 00 c6 44 24 1c 56 c6 44 24 1d 69 c6 44 24 1e 72 c6 44 24 1f 74 c6 44 24 20 75 c6 44 24 21 61 c6 44 24 23 41 c6 44 24 26 6f c6 44 24 27 63 c6 44 24 28 00 } //00 00 
	condition:
		any of ($a_*)
 
}