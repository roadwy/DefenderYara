
rule Trojan_Win32_Azorult_CH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 51 5a 36 41 0d 0a 6d 6e 48 68 53 0d 0a 6c 66 56 54 47 32 0d 90 02 04 4d 0d 0a 4d 47 53 43 0d 0a 6f 5a 65 90 00 } //01 00 
		$a_01_1 = {41 69 0d 0a 51 72 57 36 0d 0a 77 65 63 77 50 0d 0a 50 4f 64 66 55 0d 0a 47 6f 64 45 } //00 00 
	condition:
		any of ($a_*)
 
}