
rule Trojan_BAT_Crysome_AMTB{
	meta:
		description = "Trojan:BAT/Crysome!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 22 43 72 79 73 6f 6d 65 4c 6f 61 64 65 72 22 } ///create /tn "CrysomeLoader"  1
		$a_80_1 = {54 43 50 20 43 4f 4e 4e 45 43 54 45 44 21 20 53 65 6e 64 69 6e 67 20 63 6c 69 65 6e 74 20 69 6e 66 6f 2e 2e } //TCP CONNECTED! Sending client info..  1
		$a_80_2 = {43 72 79 73 6f 6d 65 2e 43 6c 69 65 6e 74 2e 57 65 62 2e 57 65 62 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 2b 3c 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 3e } //Crysome.Client.Web.WebFileDownloader+<DownloadFile>  1
		$a_80_3 = {43 72 79 73 6f 6d 65 2e 43 6c 69 65 6e 74 2e 70 64 62 } //Crysome.Client.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}