
rule Trojan_BAT_Zusy_NP_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {e0 4a fe 0c 0f 00 fe 0c 0e 00 20 01 00 00 00 59 8f ?? 00 00 01 e0 4a 61 54 fe 0c } //2
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {70 61 79 6c 6f 61 64 } //1 payload
		$a_81_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 } //1 RegSetValueEx
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}