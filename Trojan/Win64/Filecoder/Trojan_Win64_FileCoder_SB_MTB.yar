
rule Trojan_Win64_FileCoder_SB_MTB{
	meta:
		description = "Trojan:Win64/FileCoder.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 0f 32 54 3d 70 48 ff c7 0f b6 44 24 70 0a d0 88 54 24 70 48 83 ff 20 7c e4 } //2
		$a_81_1 = {42 61 62 4c 6f 63 6b 20 2f 20 52 6f 72 73 63 68 61 63 68 20 44 65 63 72 79 70 74 6f 72 20 76 32 2e 30 } //1 BabLock / Rorschach Decryptor v2.0
		$a_81_2 = {55 6e 64 6f 20 72 61 6e 73 6f 6d 77 61 72 65 20 63 68 61 6e 67 65 73 } //1 Undo ransomware changes
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}