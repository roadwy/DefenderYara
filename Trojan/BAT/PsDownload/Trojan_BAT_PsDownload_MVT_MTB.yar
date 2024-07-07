
rule Trojan_BAT_PsDownload_MVT_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {1b 28 06 00 00 06 13 0d 73 0c 00 00 0a 13 0e 11 0e 18 8d 18 00 00 01 } //2
		$a_00_1 = {77 68 6f 61 6d 69 } //1 whoami
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}