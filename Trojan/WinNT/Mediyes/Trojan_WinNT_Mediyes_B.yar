
rule Trojan_WinNT_Mediyes_B{
	meta:
		description = "Trojan:WinNT/Mediyes.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 4d 08 2b c8 83 e9 05 89 48 01 c6 00 e9 83 c0 05 5d } //1
		$a_01_1 = {66 83 f9 46 75 a6 0f b7 48 0a 66 83 f9 6f 74 06 66 83 f9 4f 75 96 0f b7 48 0c 66 83 f9 78 74 06 66 83 f9 58 75 86 66 83 78 0e 2e 0f 85 7b ff ff ff 0f b7 48 10 66 83 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}