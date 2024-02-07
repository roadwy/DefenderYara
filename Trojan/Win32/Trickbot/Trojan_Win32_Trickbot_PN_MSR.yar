
rule Trojan_Win32_Trickbot_PN_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.PN!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 0c 30 83 eb 08 32 cd 83 45 10 08 88 0c 38 8a 4c 30 01 32 cd 88 4c 38 01 8a 4c 30 02 32 cd 88 4c 38 02 8a 4c 30 03 32 cd } //01 00 
		$a_01_1 = {72 64 70 73 63 61 6e 2e 64 6c 6c } //01 00  rdpscan.dll
		$a_01_2 = {72 64 70 73 63 61 6e 2e 70 64 62 } //00 00  rdpscan.pdb
	condition:
		any of ($a_*)
 
}