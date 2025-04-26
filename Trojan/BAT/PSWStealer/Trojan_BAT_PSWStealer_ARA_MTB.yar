
rule Trojan_BAT_PSWStealer_ARA_MTB{
	meta:
		description = "Trojan:BAT/PSWStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 56 65 72 74 65 78 53 70 6f 6f 66 65 72 46 75 6c 6c 53 52 43 2e 70 64 62 } //2 \VertexSpooferFullSRC.pdb
		$a_00_1 = {3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 } //2 ://cdn.discordapp.com/attachments/
		$a_00_2 = {2f 00 70 00 65 00 72 00 6d 00 5f 00 73 00 70 00 6f 00 6f 00 66 00 65 00 72 00 2e 00 7a 00 69 00 70 00 } //2 /perm_spoofer.zip
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}