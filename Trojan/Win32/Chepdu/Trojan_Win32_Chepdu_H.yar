
rule Trojan_Win32_Chepdu_H{
	meta:
		description = "Trojan:Win32/Chepdu.H,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 } //01 00  偄⹅䱄L汄䍬湡湕潬摡潎w
		$a_01_1 = {63 3a 2f 77 69 6e 64 6f 77 73 2f 73 79 73 74 65 6d 33 32 2f 44 72 69 76 65 72 73 2f 45 74 63 2f 68 6f 73 74 73 } //01 00  c:/windows/system32/Drivers/Etc/hosts
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  SOFTWARE\Microsoft\Internet Explorer\Main
		$a_01_3 = {25 36 36 25 36 39 25 36 45 25 36 34 25 36 35 25 37 32 25 32 45 25 36 33 25 36 33 } //01 00  %66%69%6E%64%65%72%2E%63%63
		$a_01_4 = {78 78 78 2d 67 61 74 65 2e 6e 65 74 } //00 00  xxx-gate.net
	condition:
		any of ($a_*)
 
}