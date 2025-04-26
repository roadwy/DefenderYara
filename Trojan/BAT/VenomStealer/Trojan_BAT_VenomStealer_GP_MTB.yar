
rule Trojan_BAT_VenomStealer_GP_MTB{
	meta:
		description = "Trojan:BAT/VenomStealer.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 4c 77 77 63 72 4c 67 34 } //pastebin.com/raw/LwwcrLg4  1
		$a_80_1 = {50 6c 75 67 69 6e 73 5c 48 56 4e 43 53 74 75 62 2e 64 6c 6c } //Plugins\HVNCStub.dll  1
		$a_80_2 = {50 6c 75 67 69 6e 73 5c 4b 65 79 6c 6f 67 67 65 72 2e 65 78 65 } //Plugins\Keylogger.exe  1
		$a_80_3 = {52 65 67 41 73 6d 2e 65 78 65 } //RegAsm.exe  1
		$a_80_4 = {50 6c 75 67 69 6e 73 5c 53 65 6e 64 4d 65 6d 6f 72 79 2e 64 6c 6c } //Plugins\SendMemory.dll  1
		$a_80_5 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 } //discord.com/api/webhooks  1
		$a_80_6 = {43 6c 69 70 70 65 72 } //Clipper  1
		$a_80_7 = {56 65 6e 6f 6d 53 74 65 61 6c 2e 7a 69 70 } //VenomSteal.zip  1
		$a_80_8 = {50 6c 75 67 69 6e 73 5c 4c 6f 67 67 65 72 2e 64 6c 6c } //Plugins\Logger.dll  1
		$a_80_9 = {70 61 73 73 77 6f 72 64 73 2e 6a 73 6f 6e } //passwords.json  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}