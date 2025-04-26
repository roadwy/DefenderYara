
rule Ransom_Win32_Filecoder_ARA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce 8b 55 ?? 83 e1 07 c1 e1 03 e8 ?? ?? ?? ?? 8b 4d 08 30 04 0e 83 c6 01 83 d3 00 3b 5d } //2
		$a_03_1 = {8a 44 0d ec 88 81 ?? ?? ?? ?? 83 c1 01 83 d2 00 75 07 83 f9 0e 72 e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}