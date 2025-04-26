
rule TrojanDownloader_BAT_Bsymem_ABY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bsymem.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 0a 0a 16 0b 2b 19 06 03 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 58 0b 07 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}