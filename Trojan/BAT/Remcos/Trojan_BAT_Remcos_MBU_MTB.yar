
rule Trojan_BAT_Remcos_MBU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 12 00 28 ?? 00 00 0a 1f 0a 5d 03 1f 0a 5a 04 58 6f ?? 00 00 0a 06 07 05 } //2
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}