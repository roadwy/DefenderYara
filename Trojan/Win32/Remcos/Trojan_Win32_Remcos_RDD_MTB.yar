
rule Trojan_Win32_Remcos_RDD_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {30 77 da 89 57 d8 3e 9e 38 13 fc 93 } //02 00 
		$a_03_1 = {83 c4 0c 33 c0 8d 49 00 8b 0d 90 01 04 8b 15 90 01 04 f7 d1 03 d1 89 94 85 58 ff ff ff 40 90 00 } //01 00 
		$a_01_2 = {73 00 75 00 6e 00 64 00 61 00 79 00 6d 00 6f 00 6e 00 64 00 61 00 79 00 74 00 2e 00 70 00 6e 00 67 00 } //00 00  sundaymondayt.png
	condition:
		any of ($a_*)
 
}