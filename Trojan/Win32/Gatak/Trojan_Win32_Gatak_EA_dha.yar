
rule Trojan_Win32_Gatak_EA_dha{
	meta:
		description = "Trojan:Win32/Gatak.EA!dha,SIGNATURE_TYPE_PEHSTR,65 00 65 00 03 00 00 64 00 "
		
	strings :
		$a_01_0 = {45 56 5f 4d 4d 41 43 5f 4f 49 44 5f 44 4f 54 31 31 5f 50 52 49 53 45 5f 56 45 52 53 5f 41 53 53 57 4f 52 44 } //01 00  EV_MMAC_OID_DOT11_PRISE_VERS_ASSWORD
		$a_01_1 = {57 64 66 46 64 6f 51 75 65 72 79 53 68 75 74 64 6f 77 6e } //01 00  WdfFdoQueryShutdown
		$a_01_2 = {45 56 5f 4d 4d 41 43 5f 52 46 5f 4b 49 4c 4c 5f 57 41 49 54 33 } //00 00  EV_MMAC_RF_KILL_WAIT3
	condition:
		any of ($a_*)
 
}