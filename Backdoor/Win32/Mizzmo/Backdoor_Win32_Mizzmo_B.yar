
rule Backdoor_Win32_Mizzmo_B{
	meta:
		description = "Backdoor:Win32/Mizzmo.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 7d f8 00 75 0d 8b 55 08 8b cb c1 e9 10 ff 45 08 88 0a c1 e3 08 48 75 e7 } //02 00 
		$a_00_1 = {2e 63 6f 6d 3a 34 34 33 } //01 00  .com:443
		$a_00_2 = {2f 75 70 64 61 74 65 2f 63 68 65 63 6b 73 74 61 72 74 2e 68 74 6d 6c } //01 00  /update/checkstart.html
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 64 6f 63 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 76 69 65 77 65 72 3f 75 72 6c 3d 25 73 26 65 6d 62 65 64 64 65 64 3d 74 72 75 65 } //01 00  https://docs.google.com/viewer?url=%s&embedded=true
		$a_00_4 = {6e 65 74 2e 65 78 65 20 67 72 6f 75 70 20 22 41 64 6d 69 6e 73 2e } //01 00  net.exe group "Admins.
		$a_00_5 = {68 74 74 70 3a 2f 2f 25 73 2f 66 69 6c 65 73 2f } //00 00  http://%s/files/
	condition:
		any of ($a_*)
 
}