
rule Ransom_Win32_Crituck_A{
	meta:
		description = "Ransom:Win32/Crituck.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 16 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 63 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 } //01 00  /c ping 1.1.1.1 -n 1 -w
		$a_00_1 = {69 6e 66 6f 5f 25 2e 38 58 2e 69 6e 66 6f } //01 00  info_%.8X.info
		$a_00_2 = {43 72 79 70 74 6f 4c 75 63 6b 5f 49 6e 73 74 61 6e 63 65 } //01 00  CryptoLuck_Instance
		$a_00_3 = {5c 73 6f 73 61 64 5f 25 2e 38 58 } //01 00  \sosad_%.8X
		$a_00_4 = {67 6f 6f 70 64 61 74 65 2e 64 6c 6c } //02 00  goopdate.dll
		$a_00_5 = {4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 6e 6f 61 6d 57 7a 64 32 68 37 44 4b 7a 4d 4b 59 41 68 64 4a } //01 00  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnoamWzd2h7DKzMKYAhdJ
		$a_00_6 = {25 73 20 25 73 25 73 20 4b 45 59 2d 2d 2d 2d 2d } //01 00  %s %s%s KEY-----
		$a_00_7 = {73 68 61 64 6f 77 73 20 2f 61 6c 6c } //01 00  shadows /all
		$a_00_8 = {00 6e 65 77 77 61 6c 6c 00 } //01 00 
		$a_00_9 = {00 74 6c 65 66 74 00 } //01 00 
		$a_00_10 = {00 63 72 70 2e 63 66 67 00 } //01 00 
		$a_00_11 = {2f 61 64 64 72 65 73 73 62 61 6c 61 6e 63 65 2f 25 73 3f 63 6f 6e 66 69 72 6d 61 74 69 6f 6e 73 3d 25 64 } //01 00  /addressbalance/%s?confirmations=%d
		$a_00_12 = {25 73 3f 69 64 3d 25 2e 38 58 26 67 65 74 70 6d } //01 00  %s?id=%.8X&getpm
		$a_00_13 = {4d 73 67 4e 6f 74 41 6c 6c } //01 00  MsgNotAll
		$a_00_14 = {4d 73 67 46 69 6c 65 53 61 76 65 64 } //01 00  MsgFileSaved
		$a_00_15 = {25 73 5f 25 2e 38 58 2e 71 72 2e 70 6e 67 } //01 00  %s_%.8X.qr.png
		$a_00_16 = {3f 64 61 74 61 3d 62 69 74 63 6f 69 6e 3a 25 73 } //01 00  ?data=bitcoin:%s
		$a_00_17 = {3f 61 6d 6f 75 6e 74 3d 25 73 26 73 69 7a 65 3d } //01 00  ?amount=%s&size=
		$a_00_18 = {42 54 4e 5f 42 72 6f 77 73 65 } //01 00  BTN_Browse
		$a_00_19 = {4d 73 67 50 4b 4e 6f 74 46 6f 75 6e 64 } //01 00  MsgPKNotFound
		$a_00_20 = {4d 73 67 50 4b 4e 6f 74 56 61 6c 69 64 } //02 00  MsgPKNotValid
		$a_03_21 = {80 38 70 75 90 01 01 80 78 01 6d 75 90 01 01 80 78 02 3d 90 00 } //00 00 
		$a_00_22 = {5d 04 00 00 aa 94 } //03 80 
	condition:
		any of ($a_*)
 
}