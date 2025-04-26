
rule Trojan_BAT_Remcos_JCN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.JCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58 } //2
		$a_01_1 = {50 75 6c 62 69 63 73 66 64 66 73 61 66 73 61 66 73 61 66 73 61 66 73 61 66 61 73 } //1 Pulbicsfdfsafsafsafsafsafas
		$a_01_2 = {70 75 62 6c 73 } //1 publs
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}