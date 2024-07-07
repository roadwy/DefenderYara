
rule Backdoor_Win32_Kreen_dha{
	meta:
		description = "Backdoor:Win32/Kreen!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 69 6a 61 63 6b 64 6c 6c 78 38 36 2e 64 6c 6c } //5 hijackdllx86.dll
		$a_01_1 = {77 77 77 2e 77 69 6e 64 6f 77 73 74 69 6d 65 2e 6e 65 74 } //5 www.windowstime.net
		$a_00_2 = {5c 00 73 00 63 00 72 00 65 00 65 00 6e 00 2e 00 64 00 61 00 74 00 } //1 \screen.dat
		$a_00_3 = {25 00 73 00 3f 00 61 00 74 00 74 00 61 00 63 00 68 00 3d 00 25 00 64 00 3f 00 72 00 3d 00 25 00 73 00 } //1 %s?attach=%d?r=%s
		$a_00_4 = {25 00 73 00 3f 00 74 00 69 00 74 00 6c 00 65 00 3d 00 25 00 64 00 } //1 %s?title=%d
		$a_00_5 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 http\shell\open\command
		$a_03_6 = {c6 43 4b 22 8b 15 90 01 04 89 53 4c a1 90 01 04 8b b5 ec fe ff ff 89 43 50 8b 0d 90 01 04 89 4b 54 8b 15 90 01 04 89 53 58 a1 90 01 04 8b 95 43 ff ff ff 89 43 5c 66 8b 0d 20 10 07 10 8b 85 47 ff ff ff 66 89 4b 60 8b 8d 4b ff ff ff c6 43 62 22 89 53 63 66 8b 95 4f ff ff ff 89 43 67 89 4b 6b 8b c6 66 89 53 6f 83 c4 20 c6 43 71 22 90 00 } //5
		$a_00_7 = {b1 5c 2a c8 30 8c 05 f8 fe ff ff 40 83 f8 5c 72 ef } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*5+(#a_00_7  & 1)*5) >=12
 
}