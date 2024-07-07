
rule Worm_Win32_Gamarue_C{
	meta:
		description = "Worm:Win32/Gamarue.C,SIGNATURE_TYPE_PEHSTR,12 00 10 00 0e 00 00 "
		
	strings :
		$a_01_0 = {56 58 42 6b 59 58 52 6c 49 48 4e 6c 63 6e 5a 70 59 32 55 3d } //1 VXBkYXRlIHNlcnZpY2U=
		$a_01_1 = {58 48 64 70 62 6e 4e 32 59 32 68 76 63 33 52 63 63 33 5a 6a 61 47 39 7a 64 43 35 6c 65 47 55 3d } //2 XHdpbnN2Y2hvc3Rcc3ZjaG9zdC5leGU=
		$a_01_2 = {4c 32 64 6c 64 47 4e 74 5a 43 35 77 61 48 41 2f 2f } //5 L2dldGNtZC5waHA//
		$a_01_3 = {5c 53 6d 61 72 74 46 54 50 5c 43 6c 69 65 6e 74 20 32 2e 30 5c 46 61 76 6f 72 69 74 65 73 5c 51 75 69 63 6b 20 43 6f 6e 6e 65 63 74 5c 2a 2e 78 6d 6c } //1 \SmartFTP\Client 2.0\Favorites\Quick Connect\*.xml
		$a_01_4 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \FileZilla\recentservers.xml
		$a_01_5 = {70 72 6f 67 72 61 6d 3d 46 6c 61 73 68 46 58 50 26 77 65 62 73 69 74 65 3d } //5 program=FlashFXP&website=
		$a_01_6 = {5c 47 48 49 53 4c 45 52 5c 77 63 78 5f 66 74 70 2e 69 6e 69 73 } //1 \GHISLER\wcx_ftp.inis
		$a_01_7 = {5c 45 73 74 73 6f 66 74 5c 41 4c 46 54 50 5c 51 44 61 74 61 2e 64 61 74 } //1 \Estsoft\ALFTP\QData.dat
		$a_01_8 = {4c 6d 68 30 64 48 42 6d 62 47 39 76 5a 41 3d 3d } //1 Lmh0dHBmbG9vZA==
		$a_01_9 = {4c 6e 42 76 63 33 52 6f 64 48 52 77 5a 6d 78 76 62 32 51 3d } //1 LnBvc3RodHRwZmxvb2Q=
		$a_01_10 = {58 46 64 70 62 6c 4e 76 59 32 74 7a 4c 6e 4e 33 } //1 XFdpblNvY2tzLnN3
		$a_01_11 = {4c 6e 56 77 5a 47 46 30 5a 51 3d 3d } //1 LnVwZGF0ZQ==
		$a_01_12 = {4c 6d 52 76 64 32 35 73 62 32 46 6b } //1 LmRvd25sb2Fk
		$a_01_13 = {55 33 6c 7a 64 47 56 74 4c 6d 56 34 5a 51 3d 3d } //5 U3lzdGVtLmV4ZQ==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*5) >=16
 
}