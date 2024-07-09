
rule Trojan_BAT_Nanocore_NC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dd } //5
		$a_01_1 = {7a 55 4b 43 2e 65 78 65 } //1 zUKC.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}