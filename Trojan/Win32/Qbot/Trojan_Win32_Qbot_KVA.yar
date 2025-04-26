
rule Trojan_Win32_Qbot_KVA{
	meta:
		description = "Trojan:Win32/Qbot.KVA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 4d 65 71 78 52 42 66 68 44 } //1 PMeqxRBfhD
		$a_01_1 = {44 75 70 6c 69 63 61 74 65 49 63 6f 6e } //1 DuplicateIcon
		$a_01_2 = {49 6e 74 65 72 66 61 63 45 5c 7b 62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //1 InterfacE\{b196b287-bab4-101a-b69c-00aa00341d07
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}