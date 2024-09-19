
rule TrojanDownloader_BAT_Heracles_VS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 91 02 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b } //2
		$a_01_1 = {24 61 61 64 33 35 61 31 63 2d 66 34 31 65 2d 34 38 32 39 2d 61 66 32 38 2d 39 33 38 38 30 37 33 63 33 34 66 36 } //2 $aad35a1c-f41e-4829-af28-9388073c34f6
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}