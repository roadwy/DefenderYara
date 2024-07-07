
rule Ransom_Win32_Filecoder_OJD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.OJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 82 02 1c 8a 8b 82 0c 04 00 00 02 1c 82 8b 45 fc 0f b6 04 07 89 82 0c 04 00 00 8b 15 90 01 04 8b 82 04 04 00 00 8b 8a 00 04 00 00 8b 04 82 03 04 8a 0f b6 c8 0f b6 c3 8b 0c 8a 8b 04 82 33 0c 82 33 8a 0c 04 00 00 89 8a 10 04 00 00 a1 90 01 04 8b 4d fc 8a 80 10 04 00 00 88 01 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}