
rule TrojanDownloader_O97M_IcedID_RVS_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 6a 7c 7a 7c 71 7c 4f 7c 49 7c 76 7c 4b 7c 54 7c 48 7c 44 7c 58 7c 46 7c 5a 7c 4d 7c 55 7c 4e 7c 51 7c 47 7c 56 7c 59 22 } //1 .Pattern = "j|z|q|O|I|v|K|T|H|D|X|F|Z|M|U|N|Q|G|V|Y"
		$a_03_1 = {53 65 74 20 [0-0f] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 79 67 46 73 75 29 } //1
		$a_01_2 = {2e 52 65 70 6c 61 63 65 28 59 6f 79 31 52 63 28 30 29 2c 20 22 22 29 } //1 .Replace(Yoy1Rc(0), "")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}