
rule Trojan_Win32_Quasar_RPE_MTB{
	meta:
		description = "Trojan:Win32/Quasar.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 00 61 00 6a 00 6b 00 61 00 2e 00 78 00 79 00 7a 00 2f 00 52 00 6f 00 62 00 6c 00 6f 00 78 00 5f 00 67 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 fajka.xyz/Roblox_generator.exe
		$a_01_1 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 67 00 67 00 2f 00 63 00 38 00 47 00 68 00 52 00 70 00 62 00 6b 00 46 00 72 00 } //1 discord.gg/c8GhRpbkFr
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_3 = {4f 70 61 63 69 74 79 } //1 Opacity
		$a_01_4 = {44 65 6c 61 79 } //1 Delay
		$a_01_5 = {46 00 46 00 4c 00 6f 00 61 00 64 00 65 00 72 00 } //1 FFLoader
		$a_01_6 = {72 61 74 5c 72 61 74 } //1 rat\rat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}