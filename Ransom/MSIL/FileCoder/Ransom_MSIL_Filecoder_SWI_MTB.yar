
rule Ransom_MSIL_Filecoder_SWI_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {24 36 34 38 37 65 66 31 35 2d 38 65 31 35 2d 34 64 66 35 2d 39 63 64 66 2d 31 31 36 62 66 32 38 66 39 61 30 64 } //$6487ef15-8e15-4df5-9cdf-116bf28f9a0d  2
		$a_80_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //Your files have been encrypted  2
		$a_80_2 = {41 6c 65 72 74 61 52 61 6e 73 6f 6d } //AlertaRansom  1
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}