
rule Trojan_BAT_RedlineStealer_RPJ_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2d 00 00 0a 0a 12 00 23 00 00 00 00 00 00 24 40 28 2e 00 00 0a 0b 2b 23 08 2d 20 20 00 00 00 00 7e 41 00 00 04 7b 2c 00 00 04 2d 2f 45 02 00 00 00 23 00 00 00 df ff ff ff 2b 21 07 28 2d 00 00 0a 28 2f 00 00 0a 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedlineStealer_RPJ_MTB_2{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {4d 30 33 69 6c 6c 61 } //1 M03illa
		$a_01_1 = {44 69 73 63 6f 72 64 } //1 Discord
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 55 70 64 61 74 65 } //1 DownloadUpdate
		$a_01_3 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 55 70 64 61 74 65 } //1 CommandLineUpdate
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 55 70 64 61 74 65 } //1 DownloadAndExecuteUpdate
		$a_01_5 = {4e 6f 72 64 41 70 70 } //1 NordApp
		$a_01_6 = {41 6c 6c 57 61 6c 6c 65 74 73 } //1 AllWallets
		$a_01_7 = {43 72 79 70 74 6f 48 65 6c 70 65 72 } //1 CryptoHelper
		$a_01_8 = {55 70 64 61 74 65 53 68 6f 72 74 52 65 70 } //1 UpdateShortRep
		$a_01_9 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_01_10 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_11 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //1 LoadModule
		$a_01_12 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_13 = {52 65 61 64 42 79 74 65 } //1 ReadByte
		$a_01_14 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_15 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_16 = {43 6f 70 79 42 6c 6f 63 6b } //1 CopyBlock
		$a_01_17 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}