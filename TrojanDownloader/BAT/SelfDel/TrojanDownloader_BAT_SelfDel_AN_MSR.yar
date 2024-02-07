
rule TrojanDownloader_BAT_SelfDel_AN_MSR{
	meta:
		description = "TrojanDownloader:BAT/SelfDel.AN!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 43 6f 6e 73 6f 6c 65 41 70 70 32 5c 43 6f 6e 73 6f 6c 65 41 70 70 32 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4e 65 74 43 6c 69 65 6e 74 2e 70 64 62 } //00 00  \ConsoleApp2\ConsoleApp2\obj\Release\NetClient.pdb
	condition:
		any of ($a_*)
 
}