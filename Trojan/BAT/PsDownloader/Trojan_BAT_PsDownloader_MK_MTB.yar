
rule Trojan_BAT_PsDownloader_MK_MTB{
	meta:
		description = "Trojan:BAT/PsDownloader.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 42 43 44 45 46 47 48 4a 4b 4c 4d 4e 50 51 52 53 54 55 56 57 58 59 5a 32 33 34 35 36 37 38 39 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //20 ABCDEFGHJKLMNPQRSTUVWXYZ23456789-WindowStyle Hidden -EncodedCommand
		$a_81_1 = {74 72 79 20 7b 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 27 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 20 7d 20 63 61 74 63 68 20 7b 20 7d } //15 try { Add-MpPreference -ExclusionPath 'C:\' -ErrorAction SilentlyContinue } catch { }
		$a_81_2 = {65 78 63 6c 75 64 65 5f 63 5f 64 72 69 76 65 2e 70 73 31 } //10 exclude_c_drive.ps1
		$a_01_3 = {2f 63 20 73 74 61 72 74 20 22 22 20 22 } //5 /c start "" "
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_01_3  & 1)*5) >=50
 
}