
rule Trojan_WinNT_Stuxnet_B{
	meta:
		description = "Trojan:WinNT/Stuxnet.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 04 59 0f b7 04 4e 66 3d 30 00 72 c4 66 3d 39 00 77 be 0f b7 c0 8d 44 38 d0 6a 0a 99 5f f7 ff 41 83 f9 07 8b fa 7e db } //3
		$a_01_1 = {83 7d 0c 00 74 35 8b 45 08 0f b7 00 50 ff d3 0f b7 ce 51 89 45 fc ff d3 59 59 8b 4d fc 3b c1 75 1a 83 45 08 02 47 47 0f b7 37 ff 4d 0c 66 85 f6 75 ce } //3
		$a_01_2 = {7b 35 38 37 36 33 45 43 46 2d 38 41 43 33 2d 34 61 35 66 2d 39 34 33 30 2d 31 41 33 31 30 43 45 34 42 45 30 41 7d } //1 {58763ECF-8AC3-4a5f-9430-1A310CE4BE0A}
		$a_01_3 = {5c 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 66 00 61 00 73 00 74 00 66 00 61 00 74 00 } //1 \FileSystem\fastfat
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}