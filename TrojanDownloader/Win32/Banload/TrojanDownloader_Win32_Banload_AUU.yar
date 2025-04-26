
rule TrojanDownloader_Win32_Banload_AUU{
	meta:
		description = "TrojanDownloader:Win32/Banload.AUU,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 65 72 2e 63 70 6c } //2 Loader.cpl
		$a_01_1 = {54 00 41 00 50 00 50 00 4d 00 4f 00 44 00 } //2 TAPPMOD
		$a_01_2 = {25 49 6a 6b 67 33 37 49 55 48 47 53 41 44 34 64 61 67 75 6d 62 69 6c } //4 %Ijkg37IUHGSAD4dagumbil
		$a_01_3 = {25 23 24 38 37 33 32 67 36 61 73 64 7b 4f 46 46 2e 4c 49 4e 45 53 7d 53 47 48 38 37 79 33 32 67 38 39 30 7b 42 45 52 54 49 4f 4c 59 7d 74 62 73 6d 6e 73 70 65 6c 65 69 61 6c 65 69 65 6c 73 67 62 6b 2b 3d 28 } //5 %#$8732g6asd{OFF.LINES}SGH87y32g890{BERTIOLY}tbsmnspeleialeielsgbk+=(
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*5) >=13
 
}