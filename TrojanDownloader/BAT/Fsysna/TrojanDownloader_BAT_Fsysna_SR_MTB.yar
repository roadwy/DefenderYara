
rule TrojanDownloader_BAT_Fsysna_SR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Fsysna.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 08 6f 17 00 00 0a 0d 12 03 28 18 00 00 0a 28 19 00 00 0a 0b 08 17 58 0c 08 06 6f 1a 00 00 0a 32 dd } //2
		$a_81_1 = {53 68 69 72 61 7a 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Shiraza.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}