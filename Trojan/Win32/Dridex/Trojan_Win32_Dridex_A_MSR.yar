
rule Trojan_Win32_Dridex_A_MSR{
	meta:
		description = "Trojan:Win32/Dridex.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 51 54 6c 64 49 6b 63 41 4a 37 4c 49 54 2e 70 64 62 } //1 nQTldIkcAJ7LIT.pdb
		$a_03_1 = {8b 5c 24 20 8a 24 0b 0f b6 d8 01 fb 81 e3 ?? ?? ?? ?? 8b 7c 24 ?? 32 24 1f 8b 5c 24 ?? 88 24 0b 83 c1 ?? 8b 7c ?? ?? 39 f9 89 4c 24 ?? 89 54 24 ?? 89 74 24 ?? 0f 84 ?? ?? ?? ?? e9 } //1
		$a_00_2 = {88 3c 31 88 1c 11 0f b6 0c 31 01 f9 81 e1 ff 00 00 00 8b 7c 24 14 8a 1c 0f 8b 4c 24 1c 8b 74 24 04 32 1c 31 8b 4c 24 18 88 1c 31 83 c6 01 8b 4c 24 20 39 ce 8b 0c 24 89 4c 24 08 89 54 24 0c 89 74 24 10 74 1c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*2) >=2
 
}