
rule TrojanDownloader_BAT_FormBook_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 8e 69 0c 2b ?? 07 06 08 91 6f ?? 00 00 0a 08 25 17 59 0c 16 fe ?? 2d ?? 07 6f ?? 00 00 0a 0a 06 0d 09 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}