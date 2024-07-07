
rule Trojan_BAT_Remcos_DED_MTB{
	meta:
		description = "Trojan:BAT/Remcos.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 21 06 08 2b 09 06 18 6f 90 01 03 0a 2b 07 6f 90 01 03 0a 2b f0 72 90 00 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}