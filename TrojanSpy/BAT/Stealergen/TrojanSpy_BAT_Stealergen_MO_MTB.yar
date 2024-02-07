
rule TrojanSpy_BAT_Stealergen_MO_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 72 00 61 00 63 00 6f 00 6f 00 6e 00 2e 00 70 00 73 00 31 00 } //01 00  \racoon.ps1
		$a_01_1 = {5c 00 73 00 74 00 61 00 67 00 65 00 2e 00 70 00 73 00 31 00 } //01 00  \stage.ps1
		$a_01_2 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 20 00 64 00 61 00 74 00 61 00 20 00 65 00 78 00 66 00 69 00 6c 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  PowerShell data exfiltration
		$a_01_3 = {5c 00 72 00 65 00 6d 00 6f 00 74 00 65 00 63 00 2e 00 70 00 73 00 31 00 } //01 00  \remotec.ps1
		$a_01_4 = {2d 46 6f 72 63 65 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //01 00  -Force -ErrorAction SilentlyContinue
		$a_01_5 = {41 63 71 75 69 72 65 57 72 69 74 65 72 4c 6f 63 6b } //01 00  AcquireWriterLock
		$a_01_6 = {52 65 6c 65 61 73 65 57 72 69 74 65 72 4c 6f 63 6b } //01 00  ReleaseWriterLock
		$a_01_7 = {68 6f 73 74 66 69 6c 65 } //01 00  hostfile
		$a_01_8 = {74 6f 72 61 63 63 65 73 73 } //01 00  toraccess
		$a_01_9 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 } //01 00  FirewallDisable
		$a_01_10 = {65 78 66 69 6c 74 72 61 74 69 6f 6e } //01 00  exfiltration
		$a_01_11 = {6c 61 74 65 72 61 6c } //01 00  lateral
		$a_01_12 = {52 75 6e 50 6f 77 65 72 73 68 65 6c 6c } //01 00  RunPowershell
		$a_01_13 = {64 00 72 00 69 00 76 00 65 00 72 00 73 00 2f 00 65 00 74 00 63 00 2f 00 68 00 6f 00 73 00 74 00 73 00 } //00 00  drivers/etc/hosts
	condition:
		any of ($a_*)
 
}