
rule TrojanDropper_O97M_DarkNeuron_A_dha{
	meta:
		description = "TrojanDropper:O97M/DarkNeuron.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d } //01 00  -----BEGIN CERTIFICATE-----
		$a_03_1 = {73 20 3d 20 73 20 26 20 22 90 01 40 22 90 00 } //01 00 
		$a_01_2 = {2d 2d 2d 2d 2d 45 4e 44 20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d } //01 00  -----END CERTIFICATE-----
		$a_01_3 = {5c 5c 53 69 67 6e 61 74 75 72 65 2e 63 72 74 } //01 00  \\Signature.crt
		$a_01_4 = {2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 22 20 26 20 } //01 00  .Run "cmd.exe /c certutil -decode " & 
		$a_01_5 = {22 5c 5c 53 69 67 6e 2e 65 78 65 22 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e } //01 00  "\\Sign.exe", windowStyle, waitOnReturn
		$a_01_6 = {3d 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 } //01 00  =AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
		$a_01_7 = {46 75 6e 63 74 69 6f 6e 20 73 32 28 29 20 41 73 20 53 74 72 69 6e 67 } //01 00  Function s2() As String
		$a_01_8 = {44 69 6d 20 77 69 6e 64 6f 77 53 74 79 6c 65 20 41 73 20 49 6e 74 65 67 65 72 3a 20 77 69 6e 64 6f 77 53 74 79 6c 65 20 3d 20 30 } //01 00  Dim windowStyle As Integer: windowStyle = 0
		$a_01_9 = {44 69 6d 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 20 41 73 20 42 6f 6f 6c 65 61 6e 3a 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 20 3d 20 54 72 75 65 } //01 00  Dim waitOnReturn As Boolean: waitOnReturn = True
		$a_01_10 = {53 65 74 20 77 73 68 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set wsh = VBA.CreateObject("WScript.Shell")
		$a_01_11 = {46 69 6c 65 6f 75 74 2e 57 72 69 74 65 20 53 74 72 52 65 76 65 72 73 65 28 73 32 28 29 20 26 20 73 29 } //01 00  Fileout.Write StrReverse(s2() & s)
		$a_01_12 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //00 00  Set fso = CreateObject("Scripting.FileSystemObject")
	condition:
		any of ($a_*)
 
}