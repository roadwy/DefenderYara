
rule Trojan_Win32_Emotet_PEL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 16 03 ca 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 00 ff ff ff 41 8a 8c 0d ?? ?? ?? ?? 8b 55 ?? 32 0c 3a 88 0f } //1
		$a_81_1 = {30 57 6d 66 4c 6a 4e 51 49 71 55 74 77 74 76 61 64 6c 78 4e 58 43 3f 79 7e 78 62 65 4b 7e 24 75 4c 6b 4f 51 61 25 3f 7e 57 6a 34 61 33 23 4c 75 } //1 0WmfLjNQIqUtwtvadlxNXC?y~xbeK~$uLkOQa%?~Wj4a3#Lu
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}