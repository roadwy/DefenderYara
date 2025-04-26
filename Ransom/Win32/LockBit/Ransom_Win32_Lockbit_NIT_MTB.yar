
rule Ransom_Win32_Lockbit_NIT_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 54 30 02 8b 0c fb 8b c1 c1 e8 18 88 46 fe 8b c1 c1 e8 10 88 46 ff 8b c1 c1 e8 08 88 06 8b c2 c1 e8 18 8d 76 08 88 46 fa 8b c2 c1 e8 10 88 46 fb 8b c2 c1 e8 08 47 88 46 fc 8b 45 fc 88 4e f9 88 56 fd 83 ff 08 } //2
		$a_01_1 = {4a 8d 76 fc 8b 46 04 85 d2 7e 04 8b 0e eb 02 8b cf c1 e9 1d c1 e0 03 0b c8 89 4c 95 e8 85 d2 75 df } //1
		$a_01_2 = {54 6f 72 20 42 72 6f 77 73 65 72 } //1 Tor Browser
		$a_01_3 = {64 61 74 61 20 69 73 20 63 6f 6d 70 6c 65 74 65 6c 79 20 65 6e 63 72 79 70 74 65 64 } //1 data is completely encrypted
		$a_01_4 = {64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 73 } //1 decryption keys
		$a_01_5 = {52 65 79 6f 6e 70 68 61 72 6d 5f 68 61 63 6b 65 64 } //1 Reyonpharm_hacked
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}