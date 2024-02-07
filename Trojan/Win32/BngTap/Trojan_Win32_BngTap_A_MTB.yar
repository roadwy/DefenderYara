
rule Trojan_Win32_BngTap_A_MTB{
	meta:
		description = "Trojan:Win32/BngTap.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 22 25 73 22 } //01 00  cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del "%s"
		$a_81_1 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00  Select * From AntiVirusProduct
		$a_81_2 = {2f 61 70 69 2f 70 72 69 6d 65 77 69 72 65 2f 25 73 2f 72 65 71 75 65 73 74 73 } //01 00  /api/primewire/%s/requests
		$a_81_3 = {54 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 20 25 73 20 2f 46 20 26 20 20 25 73 } //01 00  Taskkill /IM  %s /F &  %s
		$a_81_4 = {64 61 65 6e 65 72 79 73 3d 25 73 26 62 65 74 72 69 65 62 73 73 79 73 74 65 6d 3d 25 73 26 61 6e 77 65 6e 64 75 6e 67 3d 25 73 26 41 56 3d 25 73 26 66 72 61 6e 6b 69 65 3d 25 73 } //00 00  daenerys=%s&betriebssystem=%s&anwendung=%s&AV=%s&frankie=%s
	condition:
		any of ($a_*)
 
}