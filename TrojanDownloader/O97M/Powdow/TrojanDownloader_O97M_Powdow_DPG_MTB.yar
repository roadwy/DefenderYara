
rule TrojanDownloader_O97M_Powdow_DPG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 61 75 74 6f 5f 63 6c 6f 73 65 28 29 64 69 6d 6d 6f 64 65 73 61 73 6e 65 77 63 6c 61 73 73 32 6d 6f 64 65 73 2e 68 6f 6f 74 69 79 61 7a 65 6e 64 73 75 62 } //1 subauto_close()dimmodesasnewclass2modes.hootiyazendsub
		$a_01_1 = {27 29 2d 75 73 65 62 29 3b 73 74 61 72 74 2d 73 6c 65 65 70 22 63 61 72 35 3d 22 2d 73 65 63 6f 6e 64 73 33 22 6d 61 76 69 79 61 31 3d 63 61 72 31 2b 63 61 72 32 2b 63 61 72 33 2b 63 61 72 34 2b 22 22 2b 63 61 72 35 63 61 72 69 6e 74 65 72 66 61 63 65 5f 6e 61 6d 65 28 6d 61 76 69 79 61 31 29 73 68 65 6c 6c 69 5f 6e 61 6d 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 ')-useb);start-sleep"car5="-seconds3"maviya1=car1+car2+car3+car4+""+car5carinterface_name(maviya1)shelli_nameendfunction
		$a_01_2 = {69 5f 6e 61 6d 65 3d 6e 61 6d 65 65 6e 64 66 75 6e 63 74 69 6f 6e 70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 68 6f 6f 74 69 79 61 7a 28 29 64 69 6d 63 61 72 31 2c } //1 i_name=nameendfunctionpublicfunctionhootiyaz()dimcar1,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}