
rule Trojan_MacOS_Macsweeper_C_MTB{
	meta:
		description = "Trojan:MacOS/Macsweeper.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 61 63 53 77 65 65 70 65 72 43 4d 49 3a 20 54 72 79 69 6e 67 20 74 6f 20 64 65 6c 65 74 65 20 66 69 6c 65 73 } //01 00  MacSweeperCMI: Trying to delete files
		$a_00_1 = {63 6f 6d 2e 4b 49 56 56 69 53 6f 66 74 77 61 72 65 2e 4d 61 63 53 77 65 65 70 65 72 44 61 65 6d 6f 6e } //01 00  com.KIVViSoftware.MacSweeperDaemon
		$a_00_2 = {6f 70 65 6e 20 2d 61 20 4d 61 63 53 77 65 65 70 65 72 44 61 65 6d 6f 6e } //00 00  open -a MacSweeperDaemon
	condition:
		any of ($a_*)
 
}