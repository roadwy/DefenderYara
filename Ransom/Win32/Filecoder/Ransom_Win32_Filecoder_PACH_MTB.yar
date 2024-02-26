
rule Ransom_Win32_Filecoder_PACH_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e2 51 2e 00 00 0f b6 95 f8 fd ff ff 0f b7 85 c8 fc ff ff 0f b6 8d 98 fe ff ff 8d 04 01 81 e2 75 1c 00 00 35 85 0f 00 00 8d 04 00 8d 14 02 13 95 a0 fe ff ff 0f b6 85 60 ff ff ff 3b 85 d4 fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}