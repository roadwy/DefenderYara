
rule Trojan_Win64_Mimikatz_AMCV_MTB{
	meta:
		description = "Trojan:Win64/Mimikatz.AMCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {65 00 50 00 c7 85 ?? ?? 00 00 72 00 69 00 c7 85 ?? ?? 00 00 76 00 69 00 c7 85 ?? ?? 00 00 6c 00 65 00 c7 85 ?? ?? 00 00 67 00 65 00 c7 85 ?? ?? 00 00 20 00 28 00 c7 85 ?? ?? 00 00 25 00 73 00 } //4
		$a_01_1 = {41 0f b6 c1 8a 4c 04 20 88 4c 14 20 0f b6 45 21 41 03 c8 44 88 44 04 20 0f b6 c1 8a 4c 04 20 8a 45 20 30 0e fe c0 48 ff c6 88 45 20 49 3b f2 } //4
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 56 3a 6f 6e 20 2f 43 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 43 6f 6d 6d 61 6e 64 54 6d 70 20 2f 66 } //cmd.exe /V:on /C reg delete HKLM\Software\CommandTmp /f  1
		$a_80_3 = {50 6c 65 61 73 65 20 69 6e 70 75 74 20 69 70 2e 20 65 67 2c 20 2f 69 70 3a 78 78 2e 58 58 58 2e 78 78 2e 78 20 6f 72 20 2f 69 70 3a 78 78 78 2e 63 6f 6d } //Please input ip. eg, /ip:xx.XXX.xx.x or /ip:xxx.com  1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}