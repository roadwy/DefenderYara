
rule Trojan_BAT_LummaC_GNS_MTB{
	meta:
		description = "Trojan:BAT/LummaC.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1c 00 07 08 7e ?? ?? ?? ?? 06 7e ?? ?? ?? ?? 8e 69 6f ?? ?? ?? 0a 9a a2 00 08 17 58 0c 08 1a fe 04 0d 09 2d dc } //10
		$a_80_1 = {64 6f 77 6e 6c 6f 61 64 65 64 66 69 6c 65 2e 65 78 65 } //downloadedfile.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}