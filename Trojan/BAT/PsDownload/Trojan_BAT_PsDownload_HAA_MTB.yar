
rule Trojan_BAT_PsDownload_HAA_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.HAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 2b f5 00 2b 15 72 ?? 00 00 70 2b 15 2b 1a 2b 1f 15 2d 03 26 de 26 2b 1e 2b fa 28 ?? 00 00 0a 2b e4 28 ?? 00 00 06 2b e4 6f ?? 00 00 0a 2b df 28 ?? 00 00 0a 2b da 0a 2b df } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}