
rule Trojan_BAT_Sdnldr_GG_MTB{
	meta:
		description = "Trojan:BAT/Sdnldr.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  1
		$a_80_1 = {53 70 6f 6f 66 65 72 2e 70 64 62 } //Spoofer.pdb  1
		$a_80_2 = {2f 73 70 6f 6f 66 65 72 2e 73 79 73 } ///spoofer.sys  1
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //https://cdn.discordapp.com/attachments/  1
		$a_80_4 = {43 6c 65 61 6e 69 6e 67 } //Cleaning  1
		$a_80_5 = {44 69 73 6b 64 72 69 76 65 } //Diskdrive  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}