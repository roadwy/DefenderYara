
rule Trojan_BAT_Nanocore_ANO_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 17 07 09 09 d2 9c 08 09 06 09 06 16 6f ?? ?? ?? 0a 5d 91 9c 09 17 58 0d 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}