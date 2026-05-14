
rule Trojan_Win32_Mikey_AHB_MTB{
	meta:
		description = "Trojan:Win32/Mikey.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 6d 45 6e 43 72 79 70 74 46 69 6c 65 45 78 74 72 61 63 74 46 72 6f 6d 4d 65 6d 6f 72 79 45 78 41 } //40 PlumEnCryptFileExtractFromMemoryExA
		$a_01_1 = {50 6c 75 6d 55 6e 50 61 63 6b 4f 6e 65 46 69 6c 65 53 74 6f 72 65 49 6e 4d 65 6d 6f 72 79 41 } //30 PlumUnPackOneFileStoreInMemoryA
		$a_01_2 = {50 6c 75 6d 43 61 74 45 6e 43 72 79 70 74 4d 41 43 42 79 50 61 74 68 } //20 PlumCatEnCryptMACByPath
		$a_01_3 = {45 6e 43 69 70 68 65 72 40 43 50 6c 75 6d 43 69 70 68 65 72 41 } //10 EnCipher@CPlumCipherA
	condition:
		((#a_01_0  & 1)*40+(#a_01_1  & 1)*30+(#a_01_2  & 1)*20+(#a_01_3  & 1)*10) >=100
 
}