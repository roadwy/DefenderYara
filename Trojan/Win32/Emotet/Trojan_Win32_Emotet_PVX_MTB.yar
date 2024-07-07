
rule Trojan_Win32_Emotet_PVX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 01 04 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 08 90 09 07 00 0f b6 8d 90 00 } //1
		$a_81_1 = {6f 44 43 30 47 69 71 35 54 64 69 30 56 71 6e 72 71 77 44 49 45 47 66 59 6c 6f 4a 35 74 35 66 38 74 61 47 4d 6e 48 59 } //1 oDC0Giq5Tdi0VqnrqwDIEGfYloJ5t5f8taGMnHY
		$a_81_2 = {4c 6c 68 6c 42 74 58 72 45 35 6a 58 68 50 53 6b 74 78 54 31 68 73 65 77 67 35 57 74 6c 37 61 4a 34 54 6e 68 62 6b 47 77 74 66 70 6f 72 35 58 57 66 53 79 73 37 4f 48 } //1 LlhlBtXrE5jXhPSktxT1hsewg5Wtl7aJ4TnhbkGwtfpor5XWfSys7OH
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}