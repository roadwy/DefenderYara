
rule Trojan_BAT_Rozena_N_MTB{
	meta:
		description = "Trojan:BAT/Rozena.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 16 06 09 16 12 02 28 ?? 00 00 06 0b 16 } //5
		$a_01_1 = {53 70 6f 74 69 66 79 73 2e 65 78 65 } //1 Spotifys.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}