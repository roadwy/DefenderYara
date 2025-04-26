
rule Trojan_Win64_UACBypassExp_A_MTB{
	meta:
		description = "Trojan:Win64/UACBypassExp.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion  1
		$a_80_1 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 3a } //Elevation:Administrator!new:  1
		$a_80_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //explorer.exe  1
		$a_80_3 = {7b 33 45 35 46 43 37 46 39 2d 39 41 35 31 2d 34 33 36 37 2d 39 30 36 33 2d 41 31 32 30 32 34 34 46 42 45 43 37 7d } //{3E5FC7F9-9A51-4367-9063-A120244FBEC7}  1
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 43 4d 5c 43 61 6c 69 62 72 61 74 69 6f 6e } //Software\Microsoft\Windows NT\CurrentVersion\ICM\Calibration  1
		$a_80_5 = {7b 44 32 45 37 30 34 31 42 2d 32 39 32 37 2d 34 32 66 62 2d 38 45 39 46 2d 37 43 45 39 33 42 36 44 43 39 33 37 7d } //{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}  1
		$a_80_6 = {63 6d 64 2e 65 78 65 } //cmd.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}