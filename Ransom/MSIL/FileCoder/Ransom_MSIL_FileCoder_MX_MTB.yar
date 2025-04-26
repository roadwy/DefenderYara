
rule Ransom_MSIL_FileCoder_MX_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //vssadmin delete shadows  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //wmic shadowcopy delete  1
		$a_00_3 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 63 00 61 00 74 00 61 00 6c 00 6f 00 67 00 20 00 2d 00 71 00 75 00 69 00 65 00 74 00 } //1 wbadmin delete catalog -quiet
		$a_00_4 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 your files are encrypted
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule Ransom_MSIL_FileCoder_MX_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 6c 61 6e 64 72 65 77 61 72 65 } //1 Flandreware
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 70 72 65 63 69 6f 75 73 20 64 61 74 61 } //1 encrypted your precious data
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 46 00 6c 00 61 00 6e 00 64 00 72 00 65 00 } //1 Your system have been encrypted by Flandre
		$a_01_3 = {2e 00 53 00 63 00 61 00 72 00 6c 00 65 00 74 00 } //1 .Scarlet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}