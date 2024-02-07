
rule TrojanDropper_O97M_Fendbenmias_A{
	meta:
		description = "TrojanDropper:O97M/Fendbenmias.A,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 55 73 65 72 49 64 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 44 4f 4d 41 49 4e 22 29 20 26 20 22 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 4e 41 4d 45 22 29 } //03 00  .UserId = Environ("USERDOMAIN") & "\" & Environ("USERNAME")
		$a_00_1 = {3b 6d 6f 76 65 20 24 65 6e 76 3a 75 73 65 72 70 72 6f 66 69 6c 65 5c 74 65 6d 70 2e 70 73 31 20 24 65 6e 76 3a 74 65 6d 70 5c 68 65 6c 70 2e 74 78 74 3b } //02 00  ;move $env:userprofile\temp.ps1 $env:temp\help.txt;
		$a_00_2 = {3d 20 22 46 75 6e 63 74 69 6f 6e 20 43 72 65 61 74 65 2d 41 65 73 4d 61 6e 61 67 65 64 4f 62 6a 65 63 74 7b 70 61 72 61 6d 28 5b 4f 62 6a 65 63 74 5d 24 6b 65 79 2c 5b 4f 62 6a 65 63 74 5d 24 49 56 29 24 61 65 73 4d 61 6e 61 67 65 64 20 3d } //02 00  = "Function Create-AesManagedObject{param([Object]$key,[Object]$IV)$aesManaged =
		$a_00_3 = {3d 20 24 65 6e 76 3a 74 65 6d 70 20 2b 20 27 73 6d 70 2e 6c 6f 63 61 6c 2e 63 72 74 27 3b 24 77 63 72 65 73 75 6c 74 73 20 3d } //02 00  = $env:temp + 'smp.local.crt';$wcresults =
		$a_00_4 = {3d 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 24 55 52 4c 20 2d 57 65 62 53 65 73 73 69 6f 6e 20 24 77 72 73 20 2d 4d 65 74 68 6f 64 } //02 00  = Invoke-WebRequest -Uri $URL -WebSession $wrs -Method
		$a_00_5 = {3d 20 72 6f 6f 74 66 6c 64 2e 47 65 74 54 61 73 6b 28 22 57 69 6e 5a 69 70 20 55 70 64 61 74 65 72 22 29 } //02 00  = rootfld.GetTask("WinZip Updater")
		$a_00_6 = {61 63 74 69 6f 6e 2e 61 72 67 75 6d 65 6e 74 73 20 3d 20 22 2f 63 20 6d 6f 76 65 20 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 } //01 00  action.arguments = "/c move " & Environ("TEMP") &
		$a_00_7 = {43 61 6c 6c 20 74 61 73 6b 2e 52 75 6e 28 30 29 } //00 00  Call task.Run(0)
		$a_00_8 = {cf 18 00 00 6b 34 } //cd cd 
	condition:
		any of ($a_*)
 
}