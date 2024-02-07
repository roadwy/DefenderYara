
rule Trojan_Win32_Rokratemb_A{
	meta:
		description = "Trojan:Win32/Rokratemb.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 3d 22 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 } //01 00  base64Encoded="TVqQAAMAAAAEAAAA
		$a_01_1 = {6f 75 74 46 69 6c 65 3d 73 79 73 44 69 72 26 22 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22 } //01 00  outFile=sysDir&"\rundll32.exe"
		$a_01_2 = {77 72 69 74 65 42 79 74 65 73 20 6f 75 74 46 69 6c 65 2c 20 62 61 73 65 36 34 44 65 63 6f 64 65 64 } //01 00  writeBytes outFile, base64Decoded
		$a_01_3 = {63 6f 6d 6d 61 6e 64 20 3d 6f 75 74 46 69 6c 65 20 26 22 20 73 79 73 75 70 64 61 74 65 22 } //00 00  command =outFile &" sysupdate"
	condition:
		any of ($a_*)
 
}