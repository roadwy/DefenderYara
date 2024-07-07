
rule Trojan_BAT_PsDownload_M_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 74 68 65 72 5f 63 6d 64 2e 70 64 62 } //1 ether_cmd.pdb
		$a_01_1 = {63 00 2d 00 76 00 6b 00 70 00 2e 00 72 00 75 00 } //1 c-vkp.ru
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}