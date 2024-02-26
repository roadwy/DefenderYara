
rule Ransom_Win32_Filecoder_PABS_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 03 8b ca c1 e9 18 33 c8 c1 e2 08 0f b6 c1 33 14 85 90 01 04 43 83 ee 01 75 e3 90 00 } //01 00 
		$a_80_1 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //select * from Win32_ShadowCopy  00 00 
	condition:
		any of ($a_*)
 
}