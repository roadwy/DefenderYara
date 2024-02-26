
rule Trojan_Win32_Vidar_GMR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 39 88 07 } //01 00 
		$a_01_1 = {45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //00 00  Exodus\exodus.wallet
	condition:
		any of ($a_*)
 
}