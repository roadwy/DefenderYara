
rule Ransom_Win64_Filecoder_AMX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.AMX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_1 = {69 6e 66 65 63 74 65 64 20 77 69 74 68 20 61 20 72 61 6e 73 6f 6d 77 61 72 65 20 76 69 72 75 73 } //1 infected with a ransomware virus
		$a_01_2 = {62 69 74 63 6f 69 6e 73 2e 63 6f 6d } //1 bitcoins.com
		$a_01_3 = {47 00 65 00 74 00 2d 00 57 00 6d 00 69 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 Get-WmiObject Win32_ShadowCopy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}