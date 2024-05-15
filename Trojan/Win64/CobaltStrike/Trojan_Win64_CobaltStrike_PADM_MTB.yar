
rule Trojan_Win64_CobaltStrike_PADM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 61 70 69 74 61 6c 62 61 6e 6b 61 7a 2e 61 7a 75 72 65 77 65 62 73 69 74 65 73 2e 6e 65 74 2f 61 70 69 2f 67 65 74 69 74 } //01 00  kapitalbankaz.azurewebsites.net/api/getit
		$a_01_1 = {49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 70 64 62 } //00 00  InternetExplorer.pdb
	condition:
		any of ($a_*)
 
}