
rule Trojan_BAT_BypassUAC_NC_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {5a 54 5f 52 41 54 5f 43 6c 69 65 6e 74 2e 52 65 73 6f 75 72 63 65 73 } //3 ZT_RAT_Client.Resources
		$a_81_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //2 Select * from AntivirusProduct
		$a_81_2 = {2f 67 65 74 2d 63 6c 69 70 62 6f 61 72 64 2d 74 65 78 74 } //1 /get-clipboard-text
		$a_81_3 = {2f 73 65 6e 64 2d 70 61 73 73 77 6f 72 64 73 } //1 /send-passwords
		$a_81_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //1 netsh firewall delete allowedprogram
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=10
 
}