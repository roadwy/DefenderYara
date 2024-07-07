
rule Trojan_BAT_Amadey_AB_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 00 65 00 73 00 74 00 6c 00 65 00 68 00 6f 00 73 00 74 00 73 00 2e 00 78 00 79 00 7a 00 } //1 nestlehosts.xyz
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } //1 DownloadData
		$a_01_2 = {4d 00 6f 00 64 00 64 00 65 00 64 00 20 00 70 00 61 00 72 00 61 00 6d 00 73 00 7c 00 44 00 61 00 74 00 61 00 30 00 2e 00 62 00 64 00 74 00 7c 00 41 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 2a 00 } //1 Modded params|Data0.bdt|All files|*.*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}