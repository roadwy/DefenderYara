
rule Trojan_Win64_Manuscrypt_RI_MTB{
	meta:
		description = "Trojan:Win64/Manuscrypt.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 4f 73 43 6c 69 65 6e 74 50 72 6f 6a 65 63 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 2d 65 78 65 } //1 WinOsClientProject\x64\Release-exe
		$a_01_1 = {47 00 46 00 49 00 52 00 65 00 73 00 74 00 61 00 72 00 74 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //1 GFIRestart64.exe
		$a_01_2 = {48 8b cb 41 f7 e3 44 2b da b8 05 41 10 04 41 d1 eb 44 03 da 41 c1 eb 09 41 f7 e3 44 2b da 41 d1 eb 44 03 da ba 3c 00 00 00 41 c1 eb 09 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}