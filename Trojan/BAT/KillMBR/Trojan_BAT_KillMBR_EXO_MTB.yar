
rule Trojan_BAT_KillMBR_EXO_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.EXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 06 07 02 07 ?? ?? ?? ?? ?? 20 ff 00 00 00 5f d2 9c 00 07 17 58 0b 07 20 6a 77 78 00 fe 04 0c 08 2d dd } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}