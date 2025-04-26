
rule Trojan_Win32_CobaltLoader_SL_MTB{
	meta:
		description = "Trojan:Win32/CobaltLoader.SL!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 49 41 2d 44 6f 6e 27 74 20 61 6e 61 6c 79 7a 65 21 21 41 54 32 38 21 21 } //5 CIA-Don't analyze!!AT28!!
		$a_01_1 = {43 00 49 00 41 00 2e 00 41 00 54 00 32 00 38 00 } //1 CIA.AT28
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}