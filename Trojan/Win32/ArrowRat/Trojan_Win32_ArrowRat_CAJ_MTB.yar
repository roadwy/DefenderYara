
rule Trojan_Win32_ArrowRat_CAJ_MTB{
	meta:
		description = "Trojan:Win32/ArrowRat.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 8d f8 fe 90 01 02 8a 95 f8 90 01 03 88 94 0d fc 90 01 03 8b 85 f8 90 01 03 99 f7 7d 14 8b 85 f8 90 01 03 8b 4d 10 8a 14 11 88 94 05 ec fd 90 01 02 eb 90 00 } //05 00 
		$a_03_1 = {89 8d ec fe 90 01 02 8b 8d ec 90 01 03 0f b6 94 0d fc 90 01 03 8b 45 08 03 85 f0 90 01 03 0f b6 08 33 ca 8b 55 08 03 95 f0 90 01 03 88 0a e9 90 00 } //01 00 
		$a_01_2 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 55 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  InstallUtil.exe
		$a_01_3 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  SetThreadContext
		$a_01_4 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //00 00  ResumeThread
	condition:
		any of ($a_*)
 
}