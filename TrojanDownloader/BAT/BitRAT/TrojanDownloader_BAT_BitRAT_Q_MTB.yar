
rule TrojanDownloader_BAT_BitRAT_Q_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 02 17 58 13 02 } //2 ȑ堗ȓ
		$a_01_1 = {02 8e 69 17 5b 8d } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}