
rule Trojan_BAT_FormBook_UBN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.UBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 2c 01 00 70 28 ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 06 11 08 11 04 6f ?? ?? ?? 0a } //1
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}