
rule Trojan_Win32_GuLoader_RDV_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6b 69 64 64 6c 65 20 79 6f 77 20 62 69 74 74 61 63 6c 65 } //1 kiddle yow bittacle
		$a_81_1 = {6f 70 74 6a 65 6e 65 6e 64 65 20 62 69 6c 69 6e 64 62 72 75 64 } //1 optjenende bilindbrud
		$a_81_2 = {67 65 6e 6e 65 6d 73 70 69 6c 6e 69 6e 67 20 66 6f 72 6d 69 63 61 74 69 6f 6e 20 69 6e 66 75 6e 64 69 62 75 6c 61 74 65 } //1 gennemspilning formication infundibulate
		$a_81_3 = {6b 75 6c 74 69 76 65 72 65 64 65 20 66 61 73 74 68 6f 6c 64 65 6c 73 65 6e 73 2e 65 78 65 } //1 kultiverede fastholdelsens.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}