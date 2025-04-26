
rule Trojan_Win32_ArrowRat_CAJ_MTB{
	meta:
		description = "Trojan:Win32/ArrowRat.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 8d f8 fe ?? ?? 8a 95 f8 ?? ?? ?? 88 94 0d fc ?? ?? ?? 8b 85 f8 ?? ?? ?? 99 f7 7d 14 8b 85 f8 ?? ?? ?? 8b 4d 10 8a 14 11 88 94 05 ec fd ?? ?? eb } //5
		$a_03_1 = {89 8d ec fe ?? ?? 8b 8d ec ?? ?? ?? 0f b6 94 0d fc ?? ?? ?? 8b 45 08 03 85 f0 ?? ?? ?? 0f b6 08 33 ca 8b 55 08 03 95 f0 ?? ?? ?? 88 0a e9 } //5
		$a_01_2 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 55 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 } //1 InstallUtil.exe
		$a_01_3 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_01_4 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}