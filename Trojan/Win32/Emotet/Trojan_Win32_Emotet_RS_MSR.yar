
rule Trojan_Win32_Emotet_RS_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {42 00 75 00 62 00 62 00 6c 00 65 00 42 00 72 00 65 00 61 00 6b 00 65 00 72 00 2e 00 45 00 58 00 45 00 } //1 BubbleBreaker.EXE
		$a_00_1 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
		$a_00_2 = {76 69 72 74 75 61 6c 61 6c 6c 6f 63 } //1 virtualalloc
		$a_00_3 = {53 6c 65 65 70 } //1 Sleep
		$a_03_4 = {66 0f b6 32 8b cf 66 d3 e6 42 66 f7 d6 0f b7 ce 88 28 88 48 90 01 01 03 45 90 01 01 ff 4d 90 01 01 75 90 00 } //1
		$a_03_5 = {2a c3 88 07 47 ff 4d 90 02 04 8a 02 42 3a c3 7d 90 02 04 eb 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Emotet_RS_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.RS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 33 f2 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 } //1
		$a_02_1 = {b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 90 01 04 8b 4d fc 89 08 5e 8b e5 5d 90 00 } //1
		$a_01_2 = {78 72 4d 6f 66 72 72 49 6a } //1 xrMofrrIj
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_RS_MSR_3{
	meta:
		description = "Trojan:Win32/Emotet.RS!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 3a 5c 43 7a 78 61 73 64 2e 6e 6d 6a 6b } //1 A:\Czxasd.nmjk
		$a_01_1 = {64 64 65 65 78 65 63 } //1 ddeexec
		$a_01_2 = {5b 70 72 69 6e 74 74 6f 28 22 25 31 22 2c 22 25 32 22 2c 22 25 33 22 2c 22 25 34 22 29 5d } //1 [printto("%1","%2","%3","%4")]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}