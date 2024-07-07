
rule Trojan_Win32_Lazarus_AR_MTB{
	meta:
		description = "Trojan:Win32/Lazarus.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 73 74 6f 6b 65 69 6e 76 65 73 74 6f 72 2e 63 6f 6d 2f 63 6f 6d 6d 6f 6e 2e 70 68 70 } //https://stokeinvestor.com/common.php  10
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 67 72 6f 77 74 68 69 6e 63 6f 6e 65 2e 63 6f 6d 2f 62 6f 61 72 64 2e 70 68 70 } //https://growthincone.com/board.php  10
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 69 6e 76 65 72 73 74 69 6e 67 70 75 72 70 6f 73 65 2e 63 6f 6d 2f 68 65 61 64 2e 70 68 70 } //https://inverstingpurpose.com/head.php  10
		$a_80_3 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_4 = {75 72 6c 6d 6f 6e 2e 64 6c 6c } //urlmon.dll  1
		$a_80_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=33
 
}