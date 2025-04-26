
rule TrojanDownloader_BAT_Remcos_ARM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 07 2b 0c de 17 07 2b f2 6f ?? 00 00 0a 2b f2 0a 2b f1 07 2c 06 07 6f ?? 00 00 0a dc 2b 7c } //2
		$a_01_1 = {66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 61 00 74 00 62 00 6f 00 78 00 2e 00 6d 00 6f 00 65 00 } //1 files.catbox.moe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}