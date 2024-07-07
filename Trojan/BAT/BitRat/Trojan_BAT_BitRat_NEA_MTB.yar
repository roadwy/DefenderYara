
rule Trojan_BAT_BitRat_NEA_MTB{
	meta:
		description = "Trojan:BAT/BitRat.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 03 08 17 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 58 0d 08 17 58 0c 2b de 90 00 } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}