
rule TrojanDownloader_BAT_LummaStealer_RP_MTB{
	meta:
		description = "TrojanDownloader:BAT/LummaStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 08 91 07 08 07 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_LummaStealer_RP_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/LummaStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 38 04 00 00 00 06 17 58 0a 06 1b 32 f8 } //10
		$a_03_1 = {1b 0a 17 0b 17 0c 38 ?? ?? 00 00 07 08 5a 0b 08 17 58 0c 08 06 31 f4 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}