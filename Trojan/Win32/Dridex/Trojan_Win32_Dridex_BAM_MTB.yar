
rule Trojan_Win32_Dridex_BAM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {46 57 72 6f 65 65 57 71 6f 69 6e 6e 6d 77 } //FWroeeWqoinnmw  03 00 
		$a_80_1 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  03 00 
		$a_80_2 = {46 54 54 55 55 4f 50 2e 70 64 62 } //FTTUUOP.pdb  03 00 
		$a_80_3 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  03 00 
		$a_80_4 = {62 65 65 6e 32 65 78 70 6c 6f 69 74 73 75 73 65 64 } //been2exploitsused  03 00 
		$a_80_5 = {4c 69 6e 75 78 77 65 65 6b 4b 49 6e 74 65 72 6e 65 74 33 4e 50 41 50 49 69 74 46 6f 72 43 68 72 6f 6d 65 } //LinuxweekKInternet3NPAPIitForChrome  03 00 
		$a_80_6 = {41 50 50 2e 45 58 45 } //APP.EXE  00 00 
	condition:
		any of ($a_*)
 
}