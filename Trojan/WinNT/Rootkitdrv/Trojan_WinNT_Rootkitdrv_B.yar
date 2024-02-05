
rule Trojan_WinNT_Rootkitdrv_B{
	meta:
		description = "Trojan:WinNT/Rootkitdrv.B,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c4 50 b8 7b 1d 80 7c ff d0 } //01 00 
		$a_01_1 = {49 6e 6a 65 63 74 45 79 65 } //01 00 
		$a_01_2 = {49 6e 6a 65 63 74 20 6c 6f 61 64 65 72 20 6f 6b } //01 00 
		$a_01_3 = {48 6f 6f 6b 20 6f 6b 21 } //00 00 
	condition:
		any of ($a_*)
 
}