
rule _#PUA_Block_DownloadSponsor{
	meta:
		description = "!#PUA:Block:DownloadSponsor,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 63 68 69 70 2d 73 65 63 75 72 65 64 2d 64 6f 77 6e 6c 6f 61 64 2e 64 65 } //api.chip-secured-download.de  2
		$a_80_1 = {61 66 74 65 72 64 6c 2e 70 68 70 } //afterdl.php  1
		$a_80_2 = {44 4d 52 2e 70 64 62 } //DMR.pdb  1
		$a_80_3 = {61 67 62 2d 70 72 6f 78 79 2e 70 68 70 } //agb-proxy.php  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_DownloadSponsor_2{
	meta:
		description = "!#PUA:Block:DownloadSponsor,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 48 49 50 20 53 65 63 75 72 65 64 20 49 6e 73 74 61 6c 6c 65 72 } //1 CHIP Secured Installer
		$a_81_1 = {44 4d 52 2e 65 78 65 } //1 DMR.exe
		$a_81_2 = {44 4d 52 2e 70 64 62 } //1 DMR.pdb
		$a_81_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*-100+(#a_81_4  & 1)*-100) >=3
 
}
rule _#PUA_Block_DownloadSponsor_3{
	meta:
		description = "!#PUA:Block:DownloadSponsor,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 63 68 69 70 2d 73 65 63 75 72 65 64 2d 64 6f 77 6e 6c 6f 61 64 2e 64 65 } //api.chip-secured-download.de  2
		$a_80_1 = {75 61 63 2e 70 68 70 } //uac.php  1
		$a_80_2 = {61 67 62 2d 70 72 6f 78 79 2e 70 68 70 } //agb-proxy.php  1
		$a_80_3 = {4f 43 53 61 67 62 2d 62 72 61 6e 64 65 64 2e 70 68 70 } //OCSagb-branded.php  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_DownloadSponsor_4{
	meta:
		description = "!#PUA:Block:DownloadSponsor,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 63 68 69 70 2d 73 65 63 75 72 65 64 2d 64 6f 77 6e 6c 6f 61 64 2e 64 65 } //api.chip-secured-download.de  2
		$a_80_1 = {61 66 74 65 72 64 6c 2e 70 68 70 } //afterdl.php  1
		$a_80_2 = {44 4d 52 5c 6f 62 6a 5c 44 65 62 75 67 5c 44 4d 52 2e 70 64 62 } //DMR\obj\Debug\DMR.pdb  1
		$a_80_3 = {67 65 6f 69 70 2e 70 68 70 } //geoip.php  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_DownloadSponsor_5{
	meta:
		description = "!#PUA:Block:DownloadSponsor,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 63 68 69 70 2d 73 65 63 75 72 65 64 2d 64 6f 77 6e 6c 6f 61 64 2e 64 65 } //api.chip-secured-download.de  2
		$a_80_1 = {4f 43 53 61 67 62 2d 62 72 61 6e 64 65 64 2e 70 68 70 } //OCSagb-branded.php  1
		$a_80_2 = {77 77 77 2e 63 68 69 70 2e 64 65 } //www.chip.de  1
		$a_80_3 = {61 67 62 2d 70 72 6f 78 79 2e 70 68 70 } //agb-proxy.php  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}