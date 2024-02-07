
rule Ransom_Win32_Filecoder_PE_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 45 41 44 4d 45 2e 74 78 74 } //01 00  README.txt
		$a_00_1 = {53 6f 6d 65 20 66 69 6c 65 73 20 69 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  Some files in your computer have been encrypted!
		$a_00_2 = {70 6f 77 65 72 40 72 61 6e 73 6f 6d 77 61 72 65 2e 63 6f 6d } //01 00  power@ransomware.com
		$a_02_3 = {5c 50 6f 77 65 72 52 61 6e 73 6f 6d 5c 90 02 10 5c 50 6f 77 65 72 52 61 6e 73 6f 6d 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_PE_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.PE!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 50 00 43 00 5d 00 } //01 00  [RansomPC]
		$a_01_1 = {5b 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 46 00 69 00 6c 00 65 00 73 00 5d 00 } //01 00  [RansomEncryptFiles]
		$a_01_2 = {5b 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 5d 00 } //01 00  [RansomScreenshot]
		$a_01_3 = {5b 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 4d 00 53 00 47 00 42 00 6f 00 64 00 79 00 5d 00 } //01 00  [RansomWarningMSGBody]
		$a_01_4 = {2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  .encrypted
		$a_01_5 = {52 61 6e 73 6f 6d 52 41 54 43 6c 69 65 6e 74 } //01 00  RansomRATClient
		$a_01_6 = {45 6e 63 72 79 70 74 44 65 73 6b 74 6f 70 46 69 6c 65 73 } //00 00  EncryptDesktopFiles
	condition:
		any of ($a_*)
 
}