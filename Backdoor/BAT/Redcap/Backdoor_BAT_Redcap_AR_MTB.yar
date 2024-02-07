
rule Backdoor_BAT_Redcap_AR_MTB{
	meta:
		description = "Backdoor:BAT/Redcap.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 13 04 00 11 04 28 1a 00 00 0a 00 00 09 6f } //01 00 
		$a_01_1 = {50 00 53 00 32 00 65 00 78 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  PS2exe.exe
		$a_01_2 = {50 53 32 65 78 65 2e 70 64 62 } //00 00  PS2exe.pdb
	condition:
		any of ($a_*)
 
}