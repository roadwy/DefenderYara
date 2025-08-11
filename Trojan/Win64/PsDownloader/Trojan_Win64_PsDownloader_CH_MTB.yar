
rule Trojan_Win64_PsDownloader_CH_MTB{
	meta:
		description = "Trojan:Win64/PsDownloader.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 62 61 64 57 6f 72 64 73 20 3d 20 40 28 27 6a 6f 68 6e 27 2c 27 61 62 62 79 27 2c 27 62 72 75 6e 6f 27 2c 27 67 65 6f 72 67 65 27 2c 27 61 7a 75 72 65 27 2c 27 31 32 38 30 78 31 30 32 34 27 2c 27 6a 6f 68 6e 20 64 6f 65 27 2c 27 64 69 73 70 6c 61 79 20 61 64 61 70 74 65 72 27 2c 27 68 79 70 65 72 2d 76 27 2c 27 76 6d 77 61 72 65 27 2c 27 76 69 72 74 75 61 6c 62 6f 78 27 2c 27 6b 76 6d 27 2c 27 71 65 6d 75 27 2c 27 78 65 6e 27 2c 27 70 61 72 61 6c 6c 65 6c 73 27 2c } //5 $badWords = @('john','abby','bruno','george','azure','1280x1024','john doe','display adapter','hyper-v','vmware','virtualbox','kvm','qemu','xen','parallels',
		$a_01_1 = {24 65 6e 76 3a 43 4f 4d 50 55 54 45 52 4e 41 4d 45 2e 54 6f 4c 6f 77 65 72 28 29 3b 66 6f 72 65 61 63 68 28 24 77 20 69 6e 20 24 62 61 64 57 6f 72 64 73 29 7b 69 66 28 24 63 2e 43 6f 6e 74 61 69 6e 73 28 24 77 29 29 7b 24 6d 61 74 63 68 65 73 2b 3d 22 43 6f 6d 70 75 74 65 72 3a 20 24 77 22 7d 7d 3b 74 72 79 20 7b 24 67 70 75 73 20 3d 20 47 65 74 2d 43 69 6d 49 6e 73 74 61 6e 63 65 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //5 $env:COMPUTERNAME.ToLower();foreach($w in $badWords){if($c.Contains($w)){$matches+="Computer: $w"}};try {$gpus = Get-CimInstance Win32_VideoController
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 43 6f 6d 6d 61 6e 64 20 22 24 50 72 6f 67 72 65 73 73 50 72 65 66 65 72 65 6e 63 65 3d 27 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 27 3b 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 27 68 74 74 70 } //2 powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'http
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //2 powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=14
 
}