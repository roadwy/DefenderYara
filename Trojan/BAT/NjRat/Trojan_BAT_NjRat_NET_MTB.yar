
rule Trojan_BAT_NjRat_NET_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 09 28 6d 00 00 0a 0a 08 06 16 06 8e b7 6f 6e 00 00 0a 08 6f 6f 00 00 0a 28 70 00 00 0a 11 04 6f 71 00 00 0a 6f 72 00 00 0a 13 09 de 11 } //5
		$a_01_1 = {3c 00 49 00 6e 00 6d 00 61 00 74 00 65 00 3e 00 } //2 <Inmate>
		$a_01_2 = {69 00 6d 00 61 00 67 00 65 00 2e 00 65 00 78 00 65 00 } //2 image.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}