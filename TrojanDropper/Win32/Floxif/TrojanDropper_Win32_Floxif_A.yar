
rule TrojanDropper_Win32_Floxif_A{
	meta:
		description = "TrojanDropper:Win32/Floxif.A,SIGNATURE_TYPE_PEHSTR_EXT,66 00 65 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 8b 02 8b 4d 08 03 c8 89 4d 08 8b 55 0c 83 c2 02 89 55 0c 8b 45 08 c1 e8 10 8b 4d 08 81 e1 ff ff 00 00 03 c1 89 45 08 } //100
		$a_01_1 = {eb 0f 8b 95 a0 fe ff ff 83 c2 01 89 95 a0 fe ff ff 81 bd a0 fe ff ff 81 0c 00 00 0f 83 9f 00 00 00 } //1
		$a_03_2 = {68 80 0c 00 00 68 ?? 00 02 10 e8 ?? ?? ff ff 83 c4 08 6a 00 8d 55 f0 52 68 80 0c 00 00 68 } //1
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=101
 
}