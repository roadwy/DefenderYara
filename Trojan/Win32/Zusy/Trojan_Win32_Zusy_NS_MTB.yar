
rule Trojan_Win32_Zusy_NS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {79 61 68 68 65 6c 70 65 72 2e 6e 6f 2d 69 70 2e 6f 72 67 } //2 yahhelper.no-ip.org
		$a_01_1 = {49 4e 46 45 43 54 49 4f 4e 20 50 41 54 48 } //1 INFECTION PATH
		$a_01_2 = {49 50 3d 25 73 20 43 6f 6d 70 75 74 65 72 4e 61 6d 65 3d 25 73 20 55 73 65 72 4e 61 6d 65 3d 25 73 20 41 74 74 61 63 6b 65 64 3d 25 64 2f 25 64 2f 25 64 } //1 IP=%s ComputerName=%s UserName=%s Attacked=%d/%d/%d
		$a_01_3 = {4c 41 53 54 20 4b 45 59 20 53 54 52 4f 4b 45 } //1 LAST KEY STROKE
		$a_01_4 = {4c 41 53 54 20 54 4f 4b 45 4e 20 49 4e 46 4f } //1 LAST TOKEN INFO
		$a_01_5 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //1 capCreateCaptureWindowA
		$a_01_6 = {54 68 65 43 6f 6d 70 75 74 65 72 4f 66 54 68 65 47 68 6f 73 74 } //1 TheComputerOfTheGhost
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}