
rule Trojan_Win32_Agent_EAD{
	meta:
		description = "Trojan:Win32/Agent.EAD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 f3 11 88 1c 11 8b 54 24 90 01 01 8a 1c 11 80 c3 f0 88 1c 11 41 3b c8 7c d4 90 00 } //4
		$a_00_1 = {3a 5c 61 6e 67 65 6c 2e 6a 70 67 } //1 :\angel.jpg
		$a_00_2 = {5c 66 61 63 74 6f 72 79 2e 64 6c 6c } //1 \factory.dll
		$a_00_3 = {00 64 65 76 69 63 65 2e 64 6c 6c } //1
		$a_00_4 = {5c 4d 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 73 2e 69 6e 69 } //1 \MyInformations.ini
		$a_00_5 = {00 43 6f 6e 6e 65 63 74 48 6f 73 74 } //1 䌀湯敮瑣潈瑳
		$a_00_6 = {25 73 5c 7e 25 63 43 6f 6e 6e 65 63 74 25 63 25 63 2e 74 65 6d 70 } //1 %s\~%cConnect%c%c.temp
		$a_00_7 = {3a 5c 71 71 6c 69 76 65 73 6c 6f 67 2e 73 63 72 } //1 :\qqliveslog.scr
		$a_00_8 = {25 73 2c 43 6f 64 65 4d 61 69 6e 20 25 73 } //1 %s,CodeMain %s
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}