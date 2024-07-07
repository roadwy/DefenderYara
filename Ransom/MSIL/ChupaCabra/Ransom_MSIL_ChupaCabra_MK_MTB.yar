
rule Ransom_MSIL_ChupaCabra_MK_MTB{
	meta:
		description = "Ransom:MSIL/ChupaCabra.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 77 61 72 65 } //Ransomware  1
		$a_80_1 = {48 6f 77 54 6f 44 65 63 72 79 70 74 2e 74 78 74 } //HowToDecrypt.txt  1
		$a_80_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //All your files are encrypted  1
		$a_80_3 = {68 74 74 70 3a 2f 2f 61 6e 75 62 69 73 63 6c 6f 75 64 2e 78 79 7a } //http://anubiscloud.xyz  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}