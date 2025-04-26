
rule TrojanDownloader_BAT_PsDow_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDow.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //1 ProcessWindowStyle
		$a_01_1 = {4a 49 54 53 74 61 72 74 65 72 } //2 JITStarter
		$a_01_2 = {53 6b 61 74 65 72 5f 4e 45 54 5f 4f 62 66 75 73 63 61 74 6f 72 5f } //2 Skater_NET_Obfuscator_
		$a_01_3 = {52 75 73 74 65 6d 53 6f 66 74 2e 53 6b 61 74 65 72 } //2 RustemSoft.Skater
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=7
 
}