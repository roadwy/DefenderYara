
rule Trojan_BAT_Remcos_MVA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 28 08 00 00 0a 08 28 09 00 00 0a 0d } //1
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}