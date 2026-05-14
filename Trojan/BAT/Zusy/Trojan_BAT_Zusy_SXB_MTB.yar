
rule Trojan_BAT_Zusy_SXB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 20 22 74 72 79 20 7b 20 47 65 74 2d 49 74 65 6d 50 72 6f 70 65 72 74 79 56 61 6c 75 65 20 2d 50 61 74 68 20 27 48 4b 4c 4d 3a 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 6f 66 74 77 61 72 65 50 72 6f 74 65 63 74 69 6f 6e 50 6c 61 74 66 6f 72 6d } //powershell -C "try { Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform  10
		$a_80_1 = {57 4d 49 43 20 2f 4e 6f 64 65 3a 6c 6f 63 61 6c 68 6f 73 74 20 2f 4e 61 6d 65 73 70 61 63 65 3a 5c 5c 72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 20 50 61 74 68 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 20 47 65 74 20 64 69 73 70 6c 61 79 4e 61 6d 65 20 2f 76 61 6c 75 65 } //WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName /value  5
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 47 65 74 2d 43 6c 69 70 62 6f 61 72 64 } //powershell Get-Clipboard  5
		$a_80_3 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //api.telegram.org/bot  3
		$a_80_4 = {67 65 74 6d 61 63 20 2f 46 4f 20 4c 49 53 54 } //getmac /FO LIST  1
		$a_80_5 = {77 6d 69 63 20 64 69 73 6b 64 72 69 76 65 20 67 65 74 20 73 69 7a 65 20 2f 76 61 6c 75 65 } //wmic diskdrive get size /value  1
		$a_80_6 = {77 6d 69 63 20 63 6f 6d 70 75 74 65 72 73 79 73 74 65 6d 20 67 65 74 20 74 6f 74 61 6c 70 68 79 73 69 63 61 6c 6d 65 6d 6f 72 79 20 2f 76 61 6c 75 65 } //wmic computersystem get totalphysicalmemory /value  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*3+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=26
 
}