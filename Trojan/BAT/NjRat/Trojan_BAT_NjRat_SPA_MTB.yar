
rule Trojan_BAT_NjRat_SPA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.SPA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 61 74 61 6c 68 6f 53 74 61 72 74 75 70 20 3d 20 22 24 65 6e 76 3a 41 50 50 44 41 54 41 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 75 70 64 61 74 65 2e 6c 6e 6b 22 } //2 $atalhoStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk"
		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 24 65 6e 63 55 52 4c 20 2d 4f 75 74 46 69 6c 65 20 24 65 6e 63 50 61 74 68 } //2 Invoke-WebRequest -Uri $encURL -OutFile $encPath
		$a_01_2 = {24 73 63 72 69 70 74 44 65 73 63 72 69 70 74 6f 67 72 61 66 69 61 20 3d 20 22 24 64 69 72 42 61 73 65 5c 75 70 64 61 74 65 2e 70 73 31 22 } //2 $scriptDescriptografia = "$dirBase\update.ps1"
		$a_01_3 = {24 41 74 61 6c 68 6f 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 22 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 46 69 6c 65 } //2 $Atalho.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}