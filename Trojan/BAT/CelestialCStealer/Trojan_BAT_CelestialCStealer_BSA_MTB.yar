
rule Trojan_BAT_CelestialCStealer_BSA_MTB{
	meta:
		description = "Trojan:BAT/CelestialCStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,7b 00 7b 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 65 6c 65 73 74 69 61 6c 43 2e 53 74 65 61 6c 65 72 2e 46 54 50 } //120 celestialC.Stealer.FTP
		$a_01_1 = {53 74 65 61 6c 46 54 50 } //1 StealFTP
		$a_01_2 = {42 43 52 59 50 54 5f 50 41 44 5f 50 53 53 } //1 BCRYPT_PAD_PSS
		$a_01_3 = {63 65 6c 65 73 74 69 61 6c 43 2e 53 74 65 61 6c 65 72 2e 4d 65 73 73 65 6e 67 65 72 2e 44 69 73 63 6f 72 64 } //1 celestialC.Stealer.Messenger.Discord
	condition:
		((#a_01_0  & 1)*120+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=123
 
}