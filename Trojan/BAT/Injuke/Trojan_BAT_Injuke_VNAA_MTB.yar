
rule Trojan_BAT_Injuke_VNAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.VNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1a 06 08 02 08 91 07 08 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0 } //4
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}