
rule Trojan_BAT_Disstl_FB_MTB{
	meta:
		description = "Trojan:BAT/Disstl.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //03 00  \Local Storage\leveldb
		$a_81_1 = {46 69 6e 64 54 6f 6b 65 6e 73 } //03 00  FindTokens
		$a_81_2 = {5c 64 69 73 63 6f 72 64 63 61 6e 61 72 79 } //03 00  \discordcanary
		$a_81_3 = {47 65 74 43 68 75 6e 6b 73 } //03 00  GetChunks
		$a_81_4 = {40 6d 65 2f 62 69 6c 6c 69 6e 67 2f 70 61 79 6d 65 6e 74 73 } //03 00  @me/billing/payments
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //03 00  DownloadString
		$a_81_6 = {73 69 7a 65 3d 35 31 32 } //00 00  size=512
	condition:
		any of ($a_*)
 
}