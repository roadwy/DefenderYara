
rule Trojan_BAT_Remcos_PM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 0c 08 6f ?? ?? ?? 0a 26 08 72 ?? ?? ?? 70 15 16 28 ?? ?? ?? 0a 26 08 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 26 07 0a 2b 00 06 2a } //1
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}