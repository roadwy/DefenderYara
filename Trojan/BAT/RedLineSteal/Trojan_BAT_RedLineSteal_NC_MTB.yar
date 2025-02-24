
rule Trojan_BAT_RedLineSteal_NC_MTB{
	meta:
		description = "Trojan:BAT/RedLineSteal.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {54 65 45 6e 76 69 72 6f 6e 6d 65 6e 74 6c 65 67 72 61 45 6e 76 69 72 6f 6e 6d 65 6e 74 6d 20 44 45 6e 76 69 72 6f 6e 6d 65 6e 74 65 73 6b 74 6f 45 6e 76 69 72 6f 6e 6d 65 6e 74 70 5c 74 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 61 74 61 } //2 TeEnvironmentlegraEnvironmentm DEnvironmentesktoEnvironmentp\tdEnvironmentata
		$a_81_1 = {4c 45 6e 76 69 72 6f 6e 6d 65 6e 74 6f 67 69 45 6e 76 69 72 6f 6e 6d 65 6e 74 6e 20 44 61 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 61 } //1 LEnvironmentogiEnvironmentn DatEnvironmenta
		$a_81_2 = {41 70 47 65 6e 65 72 69 63 70 44 61 47 65 6e 65 72 69 63 74 61 5c 52 47 65 6e 65 72 69 63 6f 61 6d 69 47 65 6e 65 72 69 63 6e 67 } //1 ApGenericpDaGenericta\RGenericoamiGenericng
		$a_81_3 = {42 43 72 55 6e 6d 61 6e 61 67 65 64 54 79 70 65 79 70 74 44 65 63 72 55 6e 6d 61 6e 61 67 65 64 54 79 70 65 79 70 74 } //1 BCrUnmanagedTypeyptDecrUnmanagedTypeypt
		$a_81_4 = {25 55 53 45 52 50 46 69 6c 65 2e 57 72 69 74 65 52 4f 46 49 4c 45 25 5c 41 70 70 46 69 6c 65 2e 57 72 69 74 65 44 61 74 61 5c 52 6f 61 6d 69 46 69 6c 65 2e 57 72 69 74 65 6e 67 } //1 %USERPFile.WriteROFILE%\AppFile.WriteData\RoamiFile.Writeng
		$a_81_5 = {25 55 53 45 52 50 73 65 72 76 69 63 65 49 6e 74 65 72 66 61 63 65 2e 45 78 74 65 6e 73 69 6f 6e 52 4f 46 49 4c 45 25 5c 41 70 73 65 72 76 69 63 65 49 6e 74 65 72 66 61 63 65 2e 45 78 74 65 6e 73 69 6f 6e 70 44 61 74 61 5c 4c 6f 63 61 73 65 72 76 69 63 65 49 6e 74 65 72 66 61 63 65 2e 45 78 74 65 6e 73 69 6f 6e 6c } //1 %USERPserviceInterface.ExtensionROFILE%\ApserviceInterface.ExtensionpData\LocaserviceInterface.Extensionl
		$a_81_6 = {59 61 6e 64 65 78 5c 59 61 41 64 64 6f 6e } //1 Yandex\YaAddon
		$a_81_7 = {77 61 6c 6c 65 74 } //1 wallet
		$a_81_8 = {67 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //1 get_Credentials
		$a_81_9 = {73 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 set_encrypted_key
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=11
 
}