
rule Trojan_Win32_NanoBot_MA_MTB{
	meta:
		description = "Trojan:Win32/NanoBot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f8 02 75 21 90 0a 12 00 b8 03 00 00 00 e8 [0-0b] 43 8d 43 14 e8 ?? ?? ?? ?? 8b d0 80 c2 61 8d 45 f8 e8 ?? ?? ?? ?? 8b 55 f8 8d 45 fc e8 ?? ?? ?? ?? 83 fb 06 75 } //1
		$a_00_1 = {53 31 db 69 93 08 90 40 00 05 84 08 08 42 89 93 08 90 40 00 f7 e2 89 d0 5b c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}