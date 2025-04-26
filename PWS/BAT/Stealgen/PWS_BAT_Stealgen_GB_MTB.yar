
rule PWS_BAT_Stealgen_GB_MTB{
	meta:
		description = "PWS:BAT/Stealgen.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0e 00 00 "
		
	strings :
		$a_80_0 = {4e 6f 72 64 56 50 4e } //NordVPN  1
		$a_80_1 = {3c 47 65 74 57 61 6c 6c 65 74 73 3e } //<GetWallets>  1
		$a_80_2 = {3c 50 61 72 73 65 42 72 6f 77 73 65 72 73 3e } //<ParseBrowsers>  1
		$a_80_3 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //encryptedPassword  1
		$a_80_4 = {6d 61 73 74 65 72 50 61 73 73 77 6f 72 64 } //masterPassword  1
		$a_80_5 = {54 65 6c 65 67 72 61 6d 47 72 61 62 62 65 72 } //TelegramGrabber  1
		$a_80_6 = {53 74 65 61 6d 47 72 61 62 62 65 72 } //SteamGrabber  1
		$a_80_7 = {77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 73 75 63 6b 73 } //windows defender sucks  1
		$a_80_8 = {43 72 65 64 69 74 43 61 72 64 } //CreditCard  1
		$a_80_9 = {2e 77 61 6c 6c 65 74 4d 61 73 74 65 72 63 61 72 64 } //.walletMastercard  1
		$a_80_10 = {41 6d 65 78 20 43 61 72 64 } //Amex Card  1
		$a_80_11 = {2a 2e 77 61 6c 6c 65 74 6f 72 69 67 69 6e 5f 75 72 6c } //*.walletorigin_url  1
		$a_80_12 = {55 6e 69 6f 6e 20 50 61 79 20 43 61 72 64 } //Union Pay Card  1
		$a_80_13 = {4c 61 73 65 72 20 43 61 72 64 } //Laser Card  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=10
 
}