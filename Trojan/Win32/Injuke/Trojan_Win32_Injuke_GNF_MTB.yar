
rule Trojan_Win32_Injuke_GNF_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 0f 1f 2f 00 ac 7d 2b 00 00 da 0a 00 } //10
		$a_80_1 = {56 6f 69 63 65 6d 65 65 74 65 72 20 53 65 74 75 70 } //Voicemeeter Setup  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}