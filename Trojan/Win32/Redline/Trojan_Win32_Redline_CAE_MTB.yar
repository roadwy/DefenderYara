
rule Trojan_Win32_Redline_CAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 ce f7 e1 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 0f b6 80 90 02 04 30 86 90 02 04 83 c6 05 81 fe 00 9c 04 00 0f 90 00 } //01 00 
		$a_01_1 = {5b 32 5d 20 41 75 6a 69 6e 64 79 75 } //01 00  [2] Aujindyu
		$a_01_2 = {5b 33 5d 20 53 58 61 64 65 36 37 } //00 00  [3] SXade67
	condition:
		any of ($a_*)
 
}