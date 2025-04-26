
rule Trojan_Win32_Guildma_MR{
	meta:
		description = "Trojan:Win32/Guildma.MR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6c 69 62 72 61 72 69 65 73 5c 72 61 70 74 6f 72 5c 72 61 6b 70 61 74 30 72 70 63 61 63 6b [0-05] 2e } //1
		$a_02_1 = {89 02 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 ?? ba ?? ?? ?? ?? e8 90 09 16 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}