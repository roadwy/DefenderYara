
rule Trojan_BAT_AsyncRAT_EM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 72 70 5f 70 72 6f 6a 65 2e 70 64 62 } //1 erp_proje.pdb
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {79 6f 6e 65 74 69 63 69 69 73 6c 65 6d 5f 4c 6f 61 64 } //1 yoneticiislem_Load
		$a_01_3 = {44 69 73 61 62 6c 65 45 76 65 6e 74 57 72 69 74 65 54 6f 55 6e 64 65 72 6c 79 69 6e 67 53 74 72 65 61 6d 41 73 79 6e 63 64 } //1 DisableEventWriteToUnderlyingStreamAsyncd
		$a_01_4 = {67 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 get_ConnectionString
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}