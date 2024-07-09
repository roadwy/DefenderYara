
rule Trojan_BAT_NjRat_NECZ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 da 0c 16 0d 2b 20 7e ?? ?? 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc } //10
		$a_01_1 = {47 65 74 50 69 78 65 6c } //2 GetPixel
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}