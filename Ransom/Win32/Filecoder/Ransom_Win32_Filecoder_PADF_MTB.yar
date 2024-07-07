
rule Ransom_Win32_Filecoder_PADF_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 03 32 06 46 4f 75 0a be 90 01 04 bf 09 00 00 00 88 03 83 f9 00 74 04 4b 49 eb e3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}