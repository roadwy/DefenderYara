
rule Trojan_Win32_RiseProStealer_AD_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 36 34 38 64 38 39 2d 62 30 30 63 2d 34 37 65 66 2d 39 31 30 30 2d 31 63 35 35 35 37 37 36 38 63 33 61 } //01 00  33648d89-b00c-47ef-9100-1c5557768c3a
		$a_01_1 = {50 6f 6c 79 6d 6f 64 58 54 } //01 00  PolymodXT
		$a_81_2 = {6e 69 74 4f 4b 6c 70 36 61 6e 34 72 54 69 72 71 6d 6b 75 36 33 69 74 4f 4b 75 71 61 53 37 72 65 4b 30 34 72 79 36 76 61 33 69 74 4f 4b 38 75 72 32 74 } //01 00  nitOKlp6an4rTirqmku63itOKuqaS7reK04ry6va3itOK8ur2t
		$a_81_3 = {66 61 69 6c 65 64 20 72 65 61 64 70 61 63 6b 65 74 } //01 00  failed readpacket
		$a_81_4 = {66 61 69 65 6c 64 20 73 65 6e 64 70 61 63 6b 65 74 } //00 00  faield sendpacket
	condition:
		any of ($a_*)
 
}