
rule Trojan_Linux_CobaltStrike_G_MTB{
	meta:
		description = "Trojan:Linux/CobaltStrike.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 2f 63 6f 6e 66 69 67 5f 64 65 63 72 79 70 74 2e 67 6f } //1 crypt/config_decrypt.go
		$a_01_1 = {70 61 63 6b 65 74 2f 63 6f 6d 6d 61 6e 64 73 5f 6c 69 6e 75 78 2e 67 6f } //1 packet/commands_linux.go
		$a_01_2 = {73 65 72 76 69 63 65 73 2e 43 6d 64 44 6f 77 6e 6c 6f 61 64 } //1 services.CmdDownload
		$a_01_3 = {73 65 72 76 69 63 65 73 2e 43 6d 64 53 6c 65 65 70 } //1 services.CmdSleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}