
rule Trojan_BAT_FormBook_NFC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 17 58 0a 03 25 5a 0c 03 08 58 0c } //2
		$a_01_1 = {36 64 65 35 64 39 65 63 2d 36 39 38 34 2d 34 64 35 33 2d 62 30 37 34 2d 31 34 31 39 30 61 36 36 62 30 30 66 } //1 6de5d9ec-6984-4d53-b074-14190a66b00f
		$a_03_2 = {cc 05 04 61 ?? ?? 59 06 61 45 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}