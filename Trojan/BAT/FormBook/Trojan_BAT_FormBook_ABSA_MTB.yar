
rule Trojan_BAT_FormBook_ABSA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 0b 6f ?? ?? 00 0a 13 0c 11 17 20 9f 26 26 22 5a 20 47 37 da 6c 61 38 ?? fe ff ff 00 11 17 20 e1 e3 ce bd 5a 20 f7 7d 31 c4 61 38 ?? fe ff ff 00 11 17 20 14 cf aa 52 5a 20 1f 4d 73 aa 61 38 ?? fe ff ff 11 06 11 05 6f ?? ?? 00 0a 59 13 0d 11 0d 19 fe 04 16 fe 01 13 0e 11 0e 2d 08 } //5
		$a_03_1 = {01 25 16 12 0c 28 ?? ?? 00 0a 9c 25 17 12 0c 28 ?? ?? 00 0a 9c 25 18 12 0c 28 ?? ?? 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}