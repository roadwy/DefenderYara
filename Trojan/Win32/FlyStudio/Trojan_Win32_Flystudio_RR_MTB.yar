
rule Trojan_Win32_Flystudio_RR_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,7a 00 7a 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 73 3a 2f 2f 63 6d 64 2e 63 6e 2d 6e 62 31 2e 72 61 69 6e 73 33 2e 63 6f 6d 2f [0-0f] 2e 65 78 65 } //100
		$a_03_1 = {68 74 74 70 73 3a 2f 2f 76 69 70 2e 31 32 33 70 61 6e 2e 63 6e 2f [0-0f] 2f 43 6d 64 2f [0-0f] 2e 65 78 65 } //100
		$a_03_2 = {68 74 74 70 73 3a 2f 2f 38 38 2d 31 33 34 33 31 33 32 36 33 36 2e 63 6f 73 2e 61 70 2d 6e 61 6e 6a 69 6e 67 2e 6d 79 71 63 6c 6f 75 64 2e 63 6f 6d 2f [0-0f] 2e 65 78 65 } //10
		$a_01_3 = {5c 63 6d 64 31 32 33 2e 65 78 65 } //10 \cmd123.exe
		$a_01_4 = {6b 77 6d 75 73 69 63 2e 65 78 65 } //1 kwmusic.exe
		$a_01_5 = {4b 77 53 65 72 76 69 63 65 2e 65 78 65 } //1 KwService.exe
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100+(#a_03_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=122
 
}
rule Trojan_Win32_Flystudio_RR_MTB_2{
	meta:
		description = "Trojan:Win32/Flystudio.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 74 65 6d 70 5c 61 72 69 61 32 63 2e 65 78 65 } //1 datatemp\aria2c.exe
		$a_01_1 = {2d 2d 65 6e 61 62 6c 65 2d 72 70 63 3d 74 72 75 65 20 2d 2d 72 70 63 2d 61 6c 6c 6f 77 2d 6f 72 69 67 69 6e 2d 61 6c 6c 3d 74 72 75 65 20 2d 2d 64 69 73 61 62 6c 65 2d 69 70 76 36 3d 66 61 6c 73 65 20 2d 2d 72 70 63 2d 73 65 63 72 65 74 3d } //1 --enable-rpc=true --rpc-allow-origin-all=true --disable-ipv6=false --rpc-secret=
		$a_01_2 = {2d 2d 72 70 63 2d 6c 69 73 74 65 6e 2d 70 6f 72 74 3d } //1 --rpc-listen-port=
		$a_01_3 = {00 61 72 69 61 32 63 2e 65 78 65 00 61 72 69 61 32 2e 63 6f 6e 66 00 61 72 69 61 32 2e 73 65 73 73 69 6f 6e 00 64 68 74 2e 64 61 74 00 64 68 74 36 2e 64 61 74 00 37 30 32 32 00 37 30 35 35 00 37 30 33 33 00 31 32 33 00 54 72 61 6e 73 6d 69 73 73 69 6f 6e 2f 33 2e 30 30 00 2d 54 52 33 30 30 30 2d 00 20 2d 2d 73 74 6f 70 2d 77 69 74 68 2d 70 72 6f 63 65 73 73 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}