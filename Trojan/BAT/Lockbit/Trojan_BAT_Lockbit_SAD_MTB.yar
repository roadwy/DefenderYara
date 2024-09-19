
rule Trojan_BAT_Lockbit_SAD_MTB{
	meta:
		description = "Trojan:BAT/Lockbit.SAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 69 00 70 0b 73 ?? ?? ?? 0a 0c 08 07 6f bb 00 00 0a 6f bc 00 00 0a 6f ?? ?? ?? 0a 6f be 00 00 0a 0d 09 6f bf 00 00 0a 13 04 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}