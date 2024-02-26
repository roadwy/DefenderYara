
rule Trojan_Win32_Privateloader_ASR_MTB{
	meta:
		description = "Trojan:Win32/Privateloader.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 38 20 31 30 37 20 39 32 20 31 30 30 20 31 30 33 20 32 38 20 38 33 } //01 00  28 107 92 100 103 28 83
		$a_01_1 = {39 37 20 39 31 20 31 30 34 20 31 30 30 20 39 31 20 39 38 20 34 31 20 34 30 20 33 36 20 39 30 20 39 38 20 39 38 } //00 00  97 91 104 100 91 98 41 40 36 90 98 98
	condition:
		any of ($a_*)
 
}