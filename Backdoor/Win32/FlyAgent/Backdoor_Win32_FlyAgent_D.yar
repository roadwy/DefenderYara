
rule Backdoor_Win32_FlyAgent_D{
	meta:
		description = "Backdoor:Win32/FlyAgent.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 00 00 00 00 83 04 24 06 c3 90 01 01 68 90 01 02 00 80 6a 00 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 4e 65 77 53 6f 63 6b 00 } //01 00  䜀瑥敎卷捯k
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 69 6e 53 74 61 74 69 6f 6e 73 5c 52 44 50 2d 54 63 70 } //01 00  SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 49 6e 73 74 61 6c 6c 65 72 5c 45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 } //00 00  SOFTWARE\Policies\Microsoft\Windows\Installer\EnableAdminTSRemote
	condition:
		any of ($a_*)
 
}