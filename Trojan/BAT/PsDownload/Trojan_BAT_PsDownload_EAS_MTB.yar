
rule Trojan_BAT_PsDownload_EAS_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 0c dd 03 00 00 00 26 de cf } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}