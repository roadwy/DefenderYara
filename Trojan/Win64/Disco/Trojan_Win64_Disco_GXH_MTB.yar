
rule Trojan_Win64_Disco_GXH_MTB{
	meta:
		description = "Trojan:Win64/Disco.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 56 62 6f 78 67 75 65 73 74 2e 73 79 73 73 61 6e 64 62 6f 78 76 69 72 75 73 6d 61 6c 77 61 72 65 47 6c 6f 62 61 6c 4d 65 6d 6f 72 79 53 74 61 74 75 73 45 78 47 65 74 53 79 73 74 65 6d 49 6e 66 6f 75 73 65 72 33 32 2e 64 6c 6c 47 65 74 53 79 73 74 65 6d 4d 65 74 72 69 63 73 69 70 68 6c 70 61 70 69 2e 64 6c 6c 47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f } //1 \Vboxguest.syssandboxvirusmalwareGlobalMemoryStatusExGetSystemInfouser32.dllGetSystemMetricsiphlpapi.dllGetAdaptersInfo
		$a_01_1 = {72 6f 62 6c 6f 78 73 74 65 61 6d 64 69 73 63 6f 72 64 66 61 63 65 62 6f 6f 6b 69 6e 73 74 61 67 72 61 6d 74 77 69 74 74 65 72 78 } //1 robloxsteamdiscordfacebookinstagramtwitterx
		$a_01_2 = {53 63 72 65 64 69 74 5f 63 61 72 64 73 2e 74 78 74 } //1 Scredit_cards.txt
		$a_01_3 = {72 75 73 74 5f 73 74 65 61 6c 65 72 2e 70 64 62 } //1 rust_stealer.pdb
		$a_01_4 = {73 72 63 5c 64 69 73 63 6f 72 64 2e 72 73 } //1 src\discord.rs
		$a_01_5 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 54 65 6c 65 67 72 61 6d } //1 application/jsonTelegram
		$a_01_6 = {5c 73 74 65 61 6c 74 68 2e 72 73 } //1 \stealth.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}