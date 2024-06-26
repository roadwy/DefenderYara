
rule Trojan_BAT_Coinminer_SBR_MSR{
	meta:
		description = "Trojan:BAT/Coinminer.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 72 00 62 00 66 00 74 00 70 00 2e 00 78 00 79 00 7a 00 } //01 00  http://mrbftp.xyz
		$a_01_1 = {53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 55 6e 7a 69 70 } //01 00  SecurityService.Unzip
		$a_01_2 = {57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 70 64 62 } //01 00  WindowsSecurityService.pdb
		$a_01_3 = {76 00 69 00 68 00 61 00 6e 00 73 00 6f 00 66 00 74 00 2e 00 69 00 72 00 } //00 00  vihansoft.ir
		$a_00_4 = {78 87 00 00 04 } //00 04 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Coinminer_SBR_MSR_2{
	meta:
		description = "Trojan:BAT/Coinminer.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 72 00 62 00 66 00 69 00 6c 00 65 00 2e 00 78 00 79 00 7a 00 } //01 00  http://mrbfile.xyz
		$a_01_1 = {55 00 48 00 4a 00 76 00 59 00 32 00 56 00 7a 00 63 00 30 00 68 00 68 00 59 00 32 00 74 00 6c 00 63 00 67 00 } //01 00  UHJvY2Vzc0hhY2tlcg
		$a_01_2 = {4d 00 52 00 42 00 5f 00 41 00 44 00 4d 00 49 00 4e 00 } //01 00  MRB_ADMIN
		$a_01_3 = {64 00 47 00 46 00 7a 00 61 00 32 00 31 00 6e 00 63 00 67 00 } //00 00  dGFza21ncg
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Coinminer_SBR_MSR_3{
	meta:
		description = "Trojan:BAT/Coinminer.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 69 00 68 00 61 00 6e 00 73 00 6f 00 66 00 74 00 2e 00 69 00 72 00 } //01 00  vihansoft.ir
		$a_01_1 = {53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 55 6e 7a 69 70 } //01 00  SecurityService.Unzip
		$a_01_2 = {57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 70 64 62 } //01 00  WindowsSecurityService.pdb
		$a_01_3 = {76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 2e 00 74 00 78 00 74 00 } //01 00  version.txt
		$a_01_4 = {73 00 79 00 73 00 6c 00 69 00 62 00 2e 00 64 00 6c 00 6c 00 } //01 00  syslib.dll
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 4c 4c } //00 00  DownloadDLL
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Coinminer_SBR_MSR_4{
	meta:
		description = "Trojan:BAT/Coinminer.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 79 00 73 00 74 00 65 00 6d 00 66 00 69 00 6c 00 65 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 } //01 00  http://systemfile.online
		$a_01_1 = {35 00 34 00 2e 00 33 00 36 00 2e 00 31 00 30 00 2e 00 37 00 33 00 } //01 00  54.36.10.73
		$a_01_2 = {70 00 63 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 } //01 00  pcadmin.online
		$a_01_3 = {77 00 69 00 6e 00 2e 00 64 00 6c 00 6c 00 } //01 00  win.dll
		$a_01_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 70 00 64 00 62 00 } //01 00  WindowsSecurityService.pdb
		$a_01_5 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 52 00 75 00 6e 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  WindowsRunner.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Coinminer_SBR_MSR_5{
	meta:
		description = "Trojan:BAT/Coinminer.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //01 00  https://iplogger.com
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 41 00 6c 00 65 00 78 00 75 00 69 00 6f 00 70 00 31 00 33 00 33 00 37 00 2f 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 2d 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 72 00 61 00 77 00 2f 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00 66 00 65 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  https://github.com/Alexuiop1337/Trojan-Downloader/raw/master/fee.exe
		$a_01_2 = {43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 33 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //01 00  C choice /C Y /N /D Y /T 3 & Del
		$a_01_3 = {4d 00 53 00 4f 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //01 00  MSOSecurity
		$a_01_4 = {53 00 74 00 72 00 65 00 61 00 6d 00 6d 00 2e 00 65 00 78 00 65 00 } //01 00  Streamm.exe
		$a_01_5 = {50 00 72 00 65 00 64 00 61 00 74 00 6f 00 72 00 54 00 68 00 65 00 4d 00 69 00 6e 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  PredatorTheMiner.Properties.Resources
		$a_01_6 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 } //01 00  ProcessHacker
		$a_01_7 = {2d 00 2d 00 75 00 72 00 6c 00 3d 00 7b 00 30 00 7d 00 20 00 2d 00 2d 00 75 00 73 00 65 00 72 00 3d 00 7b 00 31 00 7d 00 20 00 2d 00 2d 00 70 00 61 00 73 00 73 00 3d 00 7b 00 34 00 7d 00 20 00 2d 00 2d 00 74 00 68 00 72 00 65 00 61 00 64 00 73 00 20 00 35 00 20 00 2d 00 2d 00 64 00 6f 00 6e 00 61 00 74 00 65 00 2d 00 6c 00 65 00 76 00 65 00 6c 00 3d 00 31 00 20 00 2d 00 2d 00 6b 00 65 00 65 00 70 00 61 00 6c 00 69 00 76 00 65 00 20 00 2d 00 2d 00 72 00 65 00 74 00 72 00 69 00 65 00 73 00 3d 00 35 00 20 00 2d 00 2d 00 6d 00 61 00 78 00 2d 00 63 00 70 00 75 00 2d 00 75 00 73 00 61 00 67 00 65 00 3d 00 7b 00 33 00 7d 00 } //01 00  --url={0} --user={1} --pass={4} --threads 5 --donate-level=1 --keepalive --retries=5 --max-cpu-usage={3}
		$a_01_8 = {53 65 63 75 72 69 74 79 49 64 65 6e 74 69 66 69 65 72 } //01 00  SecurityIdentifier
		$a_01_9 = {50 72 65 64 61 74 6f 72 54 68 65 4d 69 6e 65 72 2e 70 64 62 } //00 00  PredatorTheMiner.pdb
	condition:
		any of ($a_*)
 
}