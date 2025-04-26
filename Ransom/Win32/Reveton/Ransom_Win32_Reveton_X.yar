
rule Ransom_Win32_Reveton_X{
	meta:
		description = "Ransom:Win32/Reveton.X,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3 } //10
		$a_01_1 = {47 4c 33 30 30 20 46 75 6e 63 74 69 6f 6e 20 53 74 61 72 74 20 43 6f 6d 70 6c 69 74 65 } //1 GL300 Function Start Complite
		$a_01_2 = {47 4c 33 30 30 00 00 00 ff ff ff ff 16 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1
		$a_03_3 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 90 09 03 00 c7 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*10) >=21
 
}