
rule TrojanDownloader_Win64_ThirdEye_SL_MTB{
	meta:
		description = "TrojanDownloader:Win64/ThirdEye.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_81_0 = {59 4a 63 54 45 57 57 5b 48 63 47 45 52 58 63 47 } //02 00  YJcTEWW[HcGERXcG
		$a_81_1 = {50 6b 51 64 5c 55 5b 4c 65 56 47 59 59 5d 4a 65 54 55 5a 58 4b 57 59 64 55 46 58 58 5c 54 57 49 64 46 51 51 54 5c 5a 4b 64 4a 53 48 57 } //02 00  PkQd\U[LeVGYY]JeTUZXKWYdUFXX\TWIdFQQT\ZKdJSHW
		$a_81_2 = {33 72 64 5f 65 79 65 } //00 00  3rd_eye
	condition:
		any of ($a_*)
 
}