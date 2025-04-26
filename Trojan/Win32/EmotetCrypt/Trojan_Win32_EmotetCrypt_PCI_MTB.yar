
rule Trojan_Win32_EmotetCrypt_PCI_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 14 32 04 1a 43 88 43 ff } //2
		$a_01_1 = {0f b6 04 3b 0f b6 ca 03 c1 33 d2 f7 f5 8b ea } //1
		$a_01_2 = {8b 44 24 24 8b 54 24 18 8a 0c 02 32 0c 2f 83 c0 01 83 6c 24 14 01 88 48 ff } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}