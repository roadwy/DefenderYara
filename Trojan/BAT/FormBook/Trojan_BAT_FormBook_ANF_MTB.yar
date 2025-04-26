
rule Trojan_BAT_FormBook_ANF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ANF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 31 07 11 04 11 05 6f ?? ?? ?? 0a 13 08 07 11 04 11 05 6f ?? ?? ?? 0a 13 09 11 09 28 ?? ?? ?? 0a 13 0a 09 08 11 0a 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 11 05 07 } //2
		$a_01_1 = {42 00 61 00 6e 00 6b 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 } //1 BankMachine
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}