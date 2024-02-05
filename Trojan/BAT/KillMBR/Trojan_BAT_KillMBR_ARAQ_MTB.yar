
rule Trojan_BAT_KillMBR_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {49 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 59 6f 75 } //02 00 
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  02 00 
		$a_80_2 = {53 70 79 54 68 65 53 70 79 } //SpyTheSpy  02 00 
		$a_80_3 = {46 75 63 6b 4d 42 52 } //FuckMBR  02 00 
		$a_80_4 = {4d 42 52 20 4f 76 65 72 77 72 69 74 74 65 6e 2c 20 56 69 63 74 69 6d 20 72 65 62 6f 6f 74 65 64 } //MBR Overwritten, Victim rebooted  00 00 
	condition:
		any of ($a_*)
 
}