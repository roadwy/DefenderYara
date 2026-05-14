
rule Trojan_BAT_Remcos_BAD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 16 73 3a 00 00 0a 13 04 73 3b 00 00 0a 13 05 11 04 11 05 ?? ?? 00 00 0a 11 05 ?? ?? 00 00 0a 13 08 dd 99 00 00 00 11 05 2c 07 11 05 ?? ?? 00 00 0a dc 11 04 2c 07 11 04 ?? ?? 00 00 0a dc } //4
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}