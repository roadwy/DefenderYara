
rule Trojan_BAT_PsDownload_AADZ_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.AADZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 16 06 7b ?? 0a 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 0a 00 04 25 3a ?? 00 00 00 26 7e ?? 0a 00 04 fe ?? ?? 12 00 06 73 ?? 00 00 0a 25 80 ?? 0a 00 04 28 ?? 00 00 2b 06 fe ?? ?? 12 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 2a } //4
		$a_01_1 = {52 00 71 00 77 00 6e 00 64 00 62 00 6a 00 74 00 69 00 6b 00 74 00 } //1 Rqwndbjtikt
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}