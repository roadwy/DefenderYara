
rule _#PUA_Block_MediaGet{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 79 61 6f 66 66 65 72 35 30 31 36 30 5c 79 61 6f 66 66 65 72 35 30 31 36 30 2e 65 78 65 } //\yaoffer50160\yaoffer50160.exe  2
		$a_80_1 = {6f 66 66 65 72 5f 73 69 7a 65 } //offer_size  1
		$a_80_2 = {6d 65 64 69 61 67 65 74 2e 63 6f 6d } //mediaget.com  1
		$a_80_3 = {6c 75 6d 69 6e 61 74 69 5f 6e 65 74 5f 75 70 64 61 74 65 72 5f 77 69 6e 5f 6d 65 64 69 61 67 65 74 5f 63 6f 6d } //luminati_net_updater_win_mediaget_com  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_MediaGet_2{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 5f 73 69 7a 65 } //offer_size  1
		$a_80_1 = {63 6f 6e 66 6c 69 63 74 69 6e 67 5f 62 75 6e 64 6c 65 73 } //conflicting_bundles  1
		$a_80_2 = {5c 79 61 6f 66 66 65 72 35 30 31 36 30 5c 79 61 6f 66 66 65 72 35 30 31 36 30 2e 65 78 65 } //\yaoffer50160\yaoffer50160.exe  1
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 } //Software\Opera Software  1
		$a_80_4 = {6d 65 64 69 61 67 65 74 2e 65 78 65 } //mediaget.exe  10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*10) >=13
 
}
rule _#PUA_Block_MediaGet_3{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 6d 65 64 69 61 67 65 74 5c 6d 65 64 69 61 67 65 74 2d 73 6f 75 72 63 65 73 2d 72 65 6c 65 61 73 65 5c 72 65 6c 65 61 73 65 5c 6d 65 64 69 61 67 65 74 2e 70 64 62 } //C:\mediaget\mediaget-sources-release\release\mediaget.pdb  2
		$a_80_1 = {6d 65 64 69 61 67 65 74 2e 65 78 65 } //mediaget.exe  1
		$a_80_2 = {74 76 73 68 6f 77 73 } //tvshows  1
		$a_80_3 = {6c 69 62 76 6c 63 5f 6d 65 64 69 61 5f 70 6c 61 79 65 72 5f 73 74 6f 70 } //libvlc_media_player_stop  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_MediaGet_4{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 66 6c 69 63 74 69 6e 67 5f 62 75 6e 64 6c 65 73 } //conflicting_bundles  1
		$a_80_1 = {5c 79 61 6f 66 66 65 72 35 30 31 36 30 5c 79 61 6f 66 66 65 72 35 30 31 36 30 2e 65 78 65 } //\yaoffer50160\yaoffer50160.exe  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 } //Software\Opera Software  1
		$a_80_3 = {6d 65 64 69 61 67 65 74 2e 65 78 65 } //mediaget.exe  1
		$a_80_4 = {62 75 6e 64 6c 65 2e 65 78 65 } //bundle.exe  1
		$a_00_5 = {59 61 6e 64 65 78 50 61 63 6b 53 65 74 75 70 2e 65 78 65 } //1 YandexPackSetup.exe
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule _#PUA_Block_MediaGet_5{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {62 75 6e 64 6c 65 73 } //bundles  1
		$a_80_1 = {79 61 6f 66 66 65 72 } //yaoffer  1
		$a_80_2 = {4f 70 65 72 61 } //Opera  1
		$a_80_3 = {79 61 6e 64 65 78 } //yandex  1
		$a_80_4 = {61 76 61 73 74 } //avast  1
		$a_80_5 = {6f 66 66 65 72 5f 73 69 7a 65 } //offer_size  1
		$a_80_6 = {62 75 6e 64 6c 65 73 49 6e 73 74 61 6c 6c 69 6e 67 4e 6f 77 } //bundlesInstallingNow  1
		$a_80_7 = {4d 65 64 69 61 47 65 74 } //MediaGet  1
		$a_80_8 = {6d 65 64 69 61 67 65 74 2d 61 64 6d 69 6e 2d 70 72 6f 78 79 2e 65 78 65 } //mediaget-admin-proxy.exe  1
		$a_80_9 = {6d 65 64 69 61 67 65 74 2e 63 6f 6d } //mediaget.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}
rule _#PUA_Block_MediaGet_6{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 5f 73 69 7a 65 } //offer_size  1
		$a_80_1 = {6e 6f 5f 6f 66 66 65 72 } //no_offer  1
		$a_80_2 = {79 61 6f 66 66 65 72 2c } //yaoffer,  1
		$a_80_3 = {4d 65 64 69 61 47 65 74 20 69 6e 73 74 61 6c 6c 65 72 } //MediaGet installer  1
		$a_80_4 = {6d 65 64 69 61 67 65 74 2e 65 78 65 } //mediaget.exe  1
		$a_80_5 = {79 61 6f 66 66 65 72 } //yaoffer  1
		$a_80_6 = {4d 65 64 69 61 47 65 74 32 2e 65 78 65 } //MediaGet2.exe  1
		$a_80_7 = {4d 65 64 69 61 47 65 74 } //MediaGet  1
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=8
 
}
rule _#PUA_Block_MediaGet_7{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {6d 65 64 69 61 67 65 74 2d 69 6e 73 74 61 6c 6c 65 72 2d 32 2f 62 75 6e 64 6c 65 73 2f 62 75 6e 64 6c 65 2e 70 68 70 3f 62 3d 79 61 6e 64 65 78 } //3 mediaget-installer-2/bundles/bundle.php?b=yandex
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 65 64 69 61 67 65 74 } //2 Software\Mediaget
		$a_00_2 = {5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c } //1 \Opera\Opera\
		$a_00_3 = {70 72 6f 66 69 6c 65 5c 6f 70 65 72 61 36 2e 69 6e 69 } //1 profile\opera6.ini
		$a_80_4 = {59 41 4e 44 45 58 5f 48 54 4d 4c } //YANDEX_HTML  1
		$a_80_5 = {2d 2d 62 75 6e 64 6c 65 2d 69 6e 73 74 61 6c 6c 65 64 5f 5f } //--bundle-installed__  2
		$a_80_6 = {57 6e 55 6e 69 6e 73 74 2e 65 78 65 } //WnUninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*2+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=6
 
}
rule _#PUA_Block_MediaGet_8{
	meta:
		description = "!#PUA:Block:MediaGet,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 6d 65 64 69 61 67 65 74 2d 69 6e 73 74 61 6c 6c 65 72 2d 74 6d 70 } //1 C:\TEMP\mediaget-installer-tmp
		$a_01_1 = {6d 65 64 69 61 67 65 74 2e 63 6f 6d } //1 mediaget.com
		$a_01_2 = {62 75 6e 64 6c 65 2d 61 76 61 73 74 2e 68 74 6d 6c } //1 bundle-avast.html
		$a_01_3 = {62 75 6e 64 6c 65 2d 73 61 66 65 66 69 6e 64 65 72 2d 65 6e 2e 68 74 6d 6c } //1 bundle-safefinder-en.html
		$a_01_4 = {6f 70 65 72 61 5f 69 6e 73 74 61 6c 6c 43 68 65 63 6b } //1 opera_installCheck
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}