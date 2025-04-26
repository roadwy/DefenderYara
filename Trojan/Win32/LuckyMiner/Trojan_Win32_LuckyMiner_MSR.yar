
rule Trojan_Win32_LuckyMiner_MSR{
	meta:
		description = "Trojan:Win32/LuckyMiner!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 00 75 00 63 00 6b 00 79 00 2e 00 65 00 78 00 65 00 } //1 lucky.exe
		$a_00_1 = {4c 00 75 00 63 00 6b 00 79 00 4d 00 69 00 6e 00 65 00 72 00 } //1 LuckyMiner
		$a_00_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 75 00 63 00 6b 00 79 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 72 00 75 00 2f 00 39 00 2f 00 67 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 } //1 http://luckyminer.ru/9/gate.php
		$a_01_3 = {4d 69 6e 65 72 5c 55 49 5c 55 49 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 55 49 2e 70 64 62 } //1 Miner\UI\UI\obj\Release\UI.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}