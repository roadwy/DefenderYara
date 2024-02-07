
rule Ransom_Win32_Filecoder_PH_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PH!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 62 65 69 6e 67 20 6c 6f 63 6b 65 64 } //01 00  Your personal files are being locked
		$a_01_1 = {45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 54 00 6f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //01 00  ExtensionsToEncrypt
		$a_01_2 = {2e 61 61 66 20 2e 61 65 70 20 2e 61 65 70 78 20 2e 70 6c 62 20 2e 70 72 65 6c 20 2e 70 72 70 72 6f 6a 20 2e 61 65 74 20 2e 70 70 6a 20 2e 70 73 64 } //01 00  .aaf .aep .aepx .plb .prel .prproj .aet .ppj .psd
		$a_01_3 = {45 6e 63 72 79 70 74 46 69 6c 65 73 } //00 00  EncryptFiles
	condition:
		any of ($a_*)
 
}