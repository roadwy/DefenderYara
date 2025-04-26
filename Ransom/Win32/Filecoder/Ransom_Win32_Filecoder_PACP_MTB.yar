
rule Ransom_Win32_Filecoder_PACP_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PACP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 83 c2 01 89 55 f4 81 7d f4 8c 00 00 00 73 16 8b 45 d4 03 45 f4 0f b6 08 33 4d c8 8b 55 d4 03 55 f4 88 0a eb d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}