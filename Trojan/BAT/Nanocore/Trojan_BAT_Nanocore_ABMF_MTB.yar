
rule Trojan_BAT_Nanocore_ABMF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 05 08 5d 91 07 05 03 5d 91 61 28 ?? 00 00 0a 04 05 17 58 08 5d 91 28 ?? 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a } //5
		$a_01_1 = {4e 00 74 00 68 00 2e 00 45 00 69 00 6e 00 64 00 68 00 6f 00 76 00 65 00 6e 00 2e 00 46 00 6f 00 6e 00 74 00 79 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Nth.Eindhoven.Fontys.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}