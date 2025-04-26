
rule Trojan_BAT_Remcos_AHHM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 } //2
		$a_01_1 = {44 00 61 00 73 00 68 00 42 00 6f 00 61 00 72 00 64 00 } //1 DashBoard
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}