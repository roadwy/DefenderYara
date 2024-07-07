
rule Ransom_MSIL_Filecoder_EX_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 61 63 6b 67 72 6f 75 6e 64 20 52 61 6e 73 6f 6d } //1 Background Ransom
		$a_81_1 = {70 72 65 76 65 6e 74 63 68 61 6e 67 65 64 65 73 6b 74 6f 70 2e 62 61 74 } //1 preventchangedesktop.bat
		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //1 ransomware.exe
		$a_81_3 = {4c 65 74 5f 73 42 75 69 6c 64 52 61 6e 73 6f 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 Let_sBuildRansom.Resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}