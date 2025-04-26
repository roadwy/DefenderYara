
rule Ransom_Win32_Filecoder_PAFR_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce 8b 55 ?? 83 e1 07 c1 e1 03 e8 ?? ?? ?? ?? 8b 4d ?? 30 04 0e 83 c6 01 83 d3 00 3b 5d ?? 72 ?? 77 ?? 3b f7 72 } //2
		$a_01_1 = {99 b9 34 00 00 00 f7 f9 b8 41 00 00 00 b9 47 00 00 00 80 fa 1a 0f 4d c1 02 c2 8b e5 5d c3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}