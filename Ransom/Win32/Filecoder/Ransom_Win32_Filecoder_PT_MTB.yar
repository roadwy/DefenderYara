
rule Ransom_Win32_Filecoder_PT_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 00 83 f0 15 89 c2 8b 45 f4 88 10 83 45 f4 01 83 45 f0 01 8b 45 f0 3b 45 e4 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}