
rule Trojan_BAT_FormBook_PAF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 0b 11 0a 6f ?? ?? ?? ?? 13 0c 16 13 0d 11 05 11 09 9a 13 0e 11 0e 72 09 1a 00 70 28 b4 01 00 0a 2d 1e 11 0e 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 1b 11 0e 72 [0-ff] 13 0d 07 11 0d 6f ?? ?? ?? ?? 11 0b 17 58 13 0b 11 0b 09 32 } //4
		$a_81_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}