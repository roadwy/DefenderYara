
rule Trojan_BAT_Nanocore_GZO_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.GZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 08 92 08 20 29 0e 00 00 5d 61 d2 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}