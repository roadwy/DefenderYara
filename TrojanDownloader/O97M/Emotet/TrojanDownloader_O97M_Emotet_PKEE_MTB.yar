
rule TrojanDownloader_O97M_Emotet_PKEE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PKEE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 69 6d 6c 6f 77 72 79 2e 63 6f 6d 2f 39 74 61 67 2f 4d 76 32 5a 59 59 36 31 4e 42 4f 66 38 2f } //1 jimlowry.com/9tag/Mv2ZYY61NBOf8/
	condition:
		((#a_01_0  & 1)*1) >=1
 
}