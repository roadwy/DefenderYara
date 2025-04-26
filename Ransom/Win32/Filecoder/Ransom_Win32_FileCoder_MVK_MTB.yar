
rule Ransom_Win32_FileCoder_MVK_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 3b 99 f7 f9 0f b6 44 15 ?? 30 47 fe 8d 04 3e 99 f7 f9 0f b6 44 15 f0 30 47 ff 8b 45 ec } //1
		$a_03_1 = {03 c7 99 f7 f9 0f b6 44 15 ?? 30 47 01 8b 45 e0 03 c7 99 f7 f9 0f b6 44 15 f0 30 47 02 83 c7 05 8d 04 3b 83 f8 64 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}