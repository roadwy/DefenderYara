
rule Trojan_Win32_ShellcodeLoader_AH_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeLoader.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 fe c1 c6 ?? 89 f0 c1 e8 ?? 01 f0 8d 3c 70 42 89 d0 31 d2 f7 f1 0f b6 03 43 84 c0 75 } //30
		$a_81_1 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 72 75 6e 20 2f 74 6e 20 22 57 69 6e 53 61 66 65 } //20 schtasks.exe /run /tn "WinSafe
	condition:
		((#a_03_0  & 1)*30+(#a_81_1  & 1)*20) >=50
 
}