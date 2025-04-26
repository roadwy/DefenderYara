
rule TrojanDownloader_BAT_Duplerd_A{
	meta:
		description = "TrojanDownloader:BAT/Duplerd.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 31 64 4a 54 6a 67 32 58 30 6c 45 58 51 3d 3d } //1 W1dJTjg2X0lEXQ==
		$a_01_1 = {50 46 74 75 51 48 78 38 51 47 35 64 50 67 3d 3d } //1 PFtuQHx8QG5dPg==
		$a_01_2 = {52 45 78 66 52 56 68 46 51 31 56 55 52 51 3d 3d } //1 RExfRVhFQ1VURQ==
		$a_03_3 = {20 50 4b 03 04 33 ?? 06 1f 2c 58 48 1f 14 33 } //1
		$a_00_4 = {43 00 72 00 65 00 61 00 74 00 65 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 CreateEncryptor
		$a_01_5 = {24 33 66 33 39 34 36 39 30 2d 32 39 63 62 2d 34 63 31 39 2d 62 34 64 61 2d 37 65 64 64 32 39 62 37 31 36 38 65 } //1 $3f394690-29cb-4c19-b4da-7edd29b7168e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}