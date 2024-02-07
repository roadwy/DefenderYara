
rule TrojanDropper_Linux_Avosim_A{
	meta:
		description = "TrojanDropper:Linux/Avosim.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 76 62 73 22 } //01 00  .vbs"
		$a_01_1 = {2e 52 75 6e 20 63 6d 64 } //01 00  .Run cmd
		$a_01_2 = {22 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 46 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f } //01 00  "schtasks /create /F /sc minute /mo
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  = CreateObject("WScript.Shell")
		$a_01_4 = {22 70 6f 77 65 72 73 68 65 6c 6c 20 } //00 00  "powershell 
		$a_00_5 = {8f c8 00 } //00 03 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Linux_Avosim_A_2{
	meta:
		description = "TrojanDropper:Linux/Avosim.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 64 70 61 74 68 20 3d 20 65 6e 76 73 74 72 20 26 20 66 64 6e 61 6d 65 20 26 20 22 5c 75 70 64 2e 76 62 73 22 } //01 00  updpath = envstr & fdname & "\upd.vbs"
		$a_01_1 = {64 6e 70 61 74 68 20 3d 20 65 6e 76 73 74 72 20 26 20 66 64 6e 61 6d 65 20 26 20 22 5c 64 6e 2e 70 73 31 22 } //01 00  dnpath = envstr & fdname & "\dn.ps1"
		$a_01_2 = {2e 52 75 6e 20 22 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 46 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 22 20 26 20 74 73 6b 6d 69 6e 20 26 20 22 20 2f 74 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 74 73 6b 6e 61 6d 65 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2f 74 72 20 22 20 5f } //00 00  .Run "schtasks /create /F /sc minute /mo " & tskmin & " /tn " & Chr(34) & tskname & Chr(34) & " /tr " _
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}