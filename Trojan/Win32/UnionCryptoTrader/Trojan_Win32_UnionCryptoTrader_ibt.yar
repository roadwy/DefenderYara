
rule Trojan_Win32_UnionCryptoTrader_ibt{
	meta:
		description = "Trojan:Win32/UnionCryptoTrader!ibt,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 74 65 6d 70 64 69 73 6b 31 66 6f 6c 64 65 72 22 43 3a 5c 54 45 4d 50 5c 7b 30 30 30 30 30 30 30 31 2d 30 30 30 31 2d 30 30 30 32 2d 30 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 39 44 34 44 34 7d 22 20 20 2f 49 53 5f 74 65 6d 70 } //1 /tempdisk1folder"C:\TEMP\{00000001-0001-0002-0000-000000000049D4D4}"  /IS_temp
		$a_01_1 = {52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f 56 46 52 6f } //1 RoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRo
		$a_01_2 = {55 00 6e 00 69 00 6f 00 6e 00 43 00 72 00 79 00 70 00 74 00 6f 00 54 00 72 00 61 00 64 00 65 00 72 00 53 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //3 UnionCryptoTraderSetup.exe
		$a_01_3 = {55 00 6e 00 69 00 6f 00 6e 00 43 00 72 00 79 00 70 00 74 00 6f 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 52 00 69 00 67 00 68 00 74 00 73 00 20 00 52 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 } //3 UnionCrypto Corporation. All Rights Reserved
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=5
 
}