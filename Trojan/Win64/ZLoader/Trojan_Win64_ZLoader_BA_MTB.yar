
rule Trojan_Win64_ZLoader_BA_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.BA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 53 00 70 00 65 00 65 00 63 00 68 00 5c 00 56 00 6f 00 69 00 63 00 65 00 73 00 } //1 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices
		$a_01_1 = {53 00 52 00 47 00 52 00 41 00 4d 00 4d 00 41 00 52 00 } //1 SRGRAMMAR
		$a_01_2 = {57 69 6e 64 6f 77 73 53 44 4b 37 2d 53 61 6d 70 6c 65 73 2d 6d 61 73 74 65 72 5c 77 69 6e 75 69 5c 73 70 65 65 63 68 5c 74 75 74 6f 72 69 61 6c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 43 6f 66 66 65 65 53 68 6f 70 36 2e 70 64 62 } //1 WindowsSDK7-Samples-master\winui\speech\tutorial\x64\Release\CoffeeShop6.pdb
		$a_01_3 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //1 CryptAcquireContextA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}