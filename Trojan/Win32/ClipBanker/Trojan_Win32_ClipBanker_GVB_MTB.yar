
rule Trojan_Win32_ClipBanker_GVB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec ?? c6 45 ?? 4c c6 45 ?? 6f c6 45 ?? 61 c6 45 ?? 64 c6 45 ?? 4c c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 72 c6 45 ?? 61 c6 45 ?? 72 c6 45 ?? 79 c6 45 ?? 45 c6 45 ?? 78 c6 45 ?? 41 c6 45 ?? 00 c6 45 ?? 6b c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 00 6a 00 e8 } //2
		$a_01_1 = {54 67 62 6f 74 2f 54 65 6c 65 67 72 61 6d 20 42 6f 74 20 42 61 73 65 2f 62 69 6e } //1 Tgbot/Telegram Bot Base/bin
		$a_01_2 = {6d 61 69 6e 2e 66 65 74 63 68 41 6e 64 44 65 63 72 79 70 74 } //1 main.fetchAndDecrypt
		$a_01_3 = {6d 61 69 6e 2e 74 72 79 53 65 6e 64 } //1 main.trySend
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}