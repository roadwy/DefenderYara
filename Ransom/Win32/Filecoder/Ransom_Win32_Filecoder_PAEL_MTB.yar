
rule Ransom_Win32_Filecoder_PAEL_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b cd 0f b6 44 0c 24 32 04 33 8b 4c 24 1c 88 06 b8 4f ec c4 4e 8d 0c 31 f7 e1 8b cf c1 ea 03 6b c2 1a 2b c8 2b cd } //1
		$a_01_1 = {0f b6 44 0c 27 8b 4c 24 50 32 44 31 fc 88 46 ff 81 ff 00 86 02 00 0f 82 55 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}