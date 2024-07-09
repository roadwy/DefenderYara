
rule Trojan_Win32_ClipBanker_XA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 18 33 c0 85 db 74 18 8d 0c c2 8b 74 0c ?? 8b 4c 0c ?? 31 74 c4 ?? 31 4c c4 ?? 40 3b c3 72 e8 8d 74 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 01 7c 24 14 01 7c 24 18 2b c7 89 44 24 ?? 3b c7 73 bf } //5
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_80_3 = {62 69 74 63 6f 69 6e 63 61 73 68 3a } //bitcoincash:  1
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}