
rule Trojan_Win32_Phorpiex_SM_MSR{
	meta:
		description = "Trojan:Win32/Phorpiex.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {62 69 74 63 6f 69 6e 63 61 73 68 3a 71 72 7a 75 33 6c 61 68 63 37 74 68 6b 73 74 78 64 73 6a 61 6d 79 6d 32 73 61 6b 37 38 6a 36 6d 70 79 32 33 66 6b 33 6d 78 6a } //1 bitcoincash:qrzu3lahc7thkstxdsjamym2sak78j6mpy23fk3mxj
		$a_00_1 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 31 35 2e 31 31 33 2e 39 33 2f } //1 http://185.215.113.93/
		$a_00_2 = {68 74 74 70 3a 2f 2f 66 65 65 64 6d 65 66 69 6c 65 2e 74 6f 70 2f } //1 http://feedmefile.top/
		$a_00_3 = {68 74 74 70 3a 2f 2f 67 6f 74 73 6f 6d 65 66 69 6c 65 2e 74 6f 70 2f } //1 http://gotsomefile.top/
		$a_00_4 = {68 74 74 70 3a 2f 2f 67 69 6d 6d 65 66 69 6c 65 2e 74 6f 70 2f } //1 http://gimmefile.top/
		$a_01_5 = {25 00 73 00 79 00 73 00 74 00 65 00 6d 00 64 00 72 00 69 00 76 00 65 00 25 00 } //1 %systemdrive%
		$a_01_6 = {25 00 75 00 73 00 65 00 72 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 25 00 } //1 %userprofile%
		$a_01_7 = {25 00 74 00 65 00 6d 00 70 00 25 00 } //1 %temp%
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}