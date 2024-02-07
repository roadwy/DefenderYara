
rule Trojan_Win32_QBot_AR_MSR{
	meta:
		description = "Trojan:Win32/QBot.AR!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 57 61 74 63 68 6f 68 5c 66 69 67 68 74 41 6e 64 5c 53 74 75 64 65 6e 74 61 6e 64 5c 63 61 73 65 74 68 69 72 64 5c 44 69 72 65 63 74 48 61 73 63 61 6d 70 2e 70 64 62 } //00 00  \Watchoh\fightAnd\Studentand\casethird\DirectHascamp.pdb
	condition:
		any of ($a_*)
 
}