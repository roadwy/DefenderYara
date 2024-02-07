
rule Ransom_MSIL_Cryptolocker_EP_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 30 75 72 20 66 69 7c 65 24 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 23 70 74 } //01 00  Y0ur fi|e$ have been encr#pt
		$a_81_1 = {52 61 6e 73 6f 6d 65 57 61 72 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  RansomeWare.Form1.resources
		$a_81_2 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //01 00  GetDirectories
		$a_81_3 = {47 65 74 46 69 6c 65 73 } //00 00  GetFiles
	condition:
		any of ($a_*)
 
}