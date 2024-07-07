
rule Ransom_Win32_Filecoder_PAC_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8d 04 3b 33 c8 31 4d fc 8b 45 fc 01 05 ec 14 53 00 2b 75 fc 83 0d f4 14 53 00 ff 8b ce c1 e1 90 01 01 03 4d e8 8b c6 c1 e8 90 01 01 03 45 e0 8d 14 33 33 ca 33 c8 2b f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}