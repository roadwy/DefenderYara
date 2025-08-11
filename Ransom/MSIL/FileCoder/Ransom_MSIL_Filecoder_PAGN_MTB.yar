
rule Ransom_MSIL_Filecoder_PAGN_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAGN!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 73 00 6f 00 6d 00 65 00 20 00 73 00 75 00 70 00 65 00 72 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 57 00 61 00 72 00 65 00 21 00 21 00 } //2 All your files have been encrypted with some super RansomWare!!
		$a_01_1 = {2e 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 } //2 .RANSOM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}