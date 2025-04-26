
rule Ransom_MSIL_Cryptolocker_PAG_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 50 4f 43 2e 63 6f 76 69 64 62 6c 6f } //1 RansomwarePOC.covidblo
		$a_81_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 All of your files have been encrypted.
		$a_81_2 = {2e 70 6f 72 6e 2e 74 78 74 } //1 .porn.txt
		$a_81_3 = {66 72 69 65 6e 64 6c 79 2e 63 79 62 65 72 2e 63 72 69 6d 69 6e 61 6c } //1 friendly.cyber.criminal
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}