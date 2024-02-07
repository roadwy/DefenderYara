
rule Trojan_Win32_CoinMiner_Z{
	meta:
		description = "Trojan:Win32/CoinMiner.Z,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 20 73 68 65 6c 6c 28 22 73 74 61 72 74 20 2f 62 20 2f 73 65 70 61 72 61 74 65 20 54 69 62 61 6e 6e 65 53 6f 63 6b 65 74 2e 65 78 65 20 71 75 69 63 6b 22 29 } //01 00  get shell("start /b /separate TibanneSocket.exe quick")
		$a_01_1 = {73 57 20 28 24 41 50 50 44 41 54 41 26 22 5c 22 26 62 61 73 65 36 34 44 65 63 6f 64 65 28 22 51 6d 6c 30 59 32 39 70 62 67 3d 3d 22 29 26 22 5c 22 26 62 61 73 65 36 34 44 65 63 6f 64 65 28 22 64 32 46 73 62 47 56 30 4c 6d 52 68 64 41 3d 3d 22 29 29 } //01 00  sW ($APPDATA&"\"&base64Decode("Qml0Y29pbg==")&"\"&base64Decode("d2FsbGV0LmRhdA=="))
		$a_01_2 = {73 43 20 28 24 41 50 50 44 41 54 41 26 22 5c 22 26 62 61 73 65 36 34 44 65 63 6f 64 65 28 22 51 6d 6c 30 59 32 39 70 62 67 3d 3d 22 29 26 22 5c 22 26 62 61 73 65 36 34 44 65 63 6f 64 65 28 22 59 6d 6c 30 59 32 39 70 62 69 35 6a 62 32 35 6d 22 29 } //01 00  sC ($APPDATA&"\"&base64Decode("Qml0Y29pbg==")&"\"&base64Decode("Yml0Y29pbi5jb25m")
		$a_01_3 = {70 75 74 20 22 50 4f 53 54 20 2f 63 67 69 2d 62 69 6e 2f 73 79 6e 63 2e 63 67 69 20 48 54 54 50 2f 31 2e 31 22 26 20 43 52 20 26 } //01 00  put "POST /cgi-bin/sync.cgi HTTP/1.1"& CR &
		$a_01_4 = {70 6f 73 74 20 62 36 34 73 69 6e 67 6c 65 28 62 61 73 65 36 34 45 6e 63 6f 64 65 28 63 6c 64 29 29 20 74 6f 20 75 72 6c } //00 00  post b64single(base64Encode(cld)) to url
	condition:
		any of ($a_*)
 
}