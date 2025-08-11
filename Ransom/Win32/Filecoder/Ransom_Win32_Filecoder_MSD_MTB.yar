
rule Ransom_Win32_Filecoder_MSD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.MSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 04 37 32 44 24 ?? 8b 4c 24 10 88 04 31 8b 03 89 44 24 10 8a 04 30 46 88 44 24 0f 8b 44 24 14 8b 38 8b 40 04 2b c7 3b f0 72 } //5
		$a_01_1 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
		$a_01_2 = {2e 6c 6f 63 6b 65 64 } //1 .locked
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}