
rule Trojan_Win32_Moftamarel_B{
	meta:
		description = "Trojan:Win32/Moftamarel.B,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {28 24 66 6f 6c 64 65 72 2e 69 74 65 6d 73 20 7c 20 53 65 6c 65 63 74 2d 4f 62 6a 65 63 74 20 2d 45 78 70 61 6e 64 50 72 6f 70 65 72 74 79 20 42 6f 64 79 20 7c 20 53 65 6c 65 63 74 2d 53 74 72 69 6e 67 20 5c 22 70 61 73 73 77 6f 72 64 5c 22 29 20 2d 72 65 70 6c 61 63 65 20 27 5c 73 2b 27 2c 20 27 20 27 20 2d 6a 6f 69 6e 20 27 3b 27 3b 22 } //4 ($folder.items | Select-Object -ExpandProperty Body | Select-String \"password\") -replace '\s+', ' ' -join ';';"
		$a_01_1 = {67 65 74 45 6d 61 69 6c 41 64 64 72 65 73 73 65 73 } //4 getEmailAddresses
		$a_01_2 = {67 65 74 43 72 65 64 65 6e 74 69 61 6c 73 } //4 getCredentials
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 5c 22 6f 75 74 6c 6f 6f 6b 5c 22 3b 20 53 74 61 72 74 2d 53 6c 65 65 70 20 2d 73 20 35 3b 22 } //2 powershell -Command "Start-Process -FilePath \"outlook\"; Start-Sleep -s 5;"
		$a_01_4 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 24 6f 75 74 6c 6f 6f 6b 20 3d 20 47 65 74 2d 50 72 6f 63 65 73 73 20 6f 75 74 6c 6f 6f 6b 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 3b } //2 powershell -Command "$outlook = Get-Process outlook -ErrorAction SilentlyContinue;
		$a_01_5 = {55 6e 61 62 6c 65 20 74 6f 20 73 74 61 72 74 20 70 69 70 65 } //1 Unable to start pipe
		$a_01_6 = {3f 73 74 61 72 74 4f 75 74 6c 6f 6f 6b 40 40 59 41 48 58 5a } //1 ?startOutlook@@YAHXZ
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}