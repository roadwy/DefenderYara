
rule Ransom_MSIL_Filecoder_PK_MSR{
	meta:
		description = "Ransom:MSIL/Filecoder.PK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //vssadmin delete shadows /all /quiet & wmic shadowcopy delete  2
		$a_80_1 = {2d 2d 2d 2d 3e 20 41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 3c 2d 2d 2d 2d } //----> All of your files have been encrypted <----  1
		$a_80_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 61 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 61 20 72 61 6e 73 6f 6d 77 61 72 65 20 76 69 72 75 73 } //Your computer was infected with a ransomware virus  1
		$a_80_3 = {72 65 61 64 5f 61 70 69 73 2e 74 78 74 } //read_apis.txt  1
		$a_80_4 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //Your files have been encrypted  1
		$a_80_5 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //wbadmin delete catalog -quiet  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}