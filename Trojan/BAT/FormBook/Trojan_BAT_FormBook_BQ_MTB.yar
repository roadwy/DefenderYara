
rule Trojan_BAT_FormBook_BQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 06 08 6f ?? 00 00 0a 0d 0e 04 0e 04 4a 17 58 54 07 } //2
		$a_01_1 = {58 58 0b 02 09 04 05 28 } //2 塘ȋЉ⠅
		$a_03_2 = {25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}