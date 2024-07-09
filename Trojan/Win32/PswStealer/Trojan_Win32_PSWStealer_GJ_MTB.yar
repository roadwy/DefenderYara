
rule Trojan_Win32_PSWStealer_GJ_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b d9 8a 44 0a ff 30 44 0f ff 49 75 f5 03 fb 29 5d 10 0f 84 } //5
		$a_02_1 = {0f b6 13 32 d0 c1 e8 ?? 33 04 96 43 49 75 f1 } //5
		$a_01_2 = {53 48 43 68 61 6e 67 65 4e 6f 74 69 66 79 52 65 67 69 73 74 65 72 } //1 SHChangeNotifyRegister
		$a_01_3 = {52 65 67 69 73 74 65 72 45 76 65 6e 74 53 6f 75 72 63 65 } //1 RegisterEventSource
		$a_01_4 = {73 72 61 6e 64 } //1 srand
	condition:
		((#a_01_0  & 1)*5+(#a_02_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}