
rule Trojan_BAT_Startun_HLN_MTB{
	meta:
		description = "Trojan:BAT/Startun.HLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 8f 05 00 00 01 25 71 05 00 00 01 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 d2 81 05 00 00 01 07 17 58 0b 07 06 8e 69 32 d3 } //2
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 20 22 74 72 79 20 7b 20 47 65 74 2d 49 74 65 6d 50 72 6f 70 65 72 74 79 56 61 6c 75 65 20 2d 50 61 74 68 20 27 48 4b 4c 4d 3a 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 6f 66 74 77 61 72 65 50 72 6f 74 65 63 74 69 6f 6e 50 6c 61 74 66 6f 72 6d } //powershell -C "try { Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}