
rule Trojan_BAT_CryptInject_MBS_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 2b 76 03 02 61 20 00 01 00 00 28 ?? 00 00 06 59 06 61 } //2
		$a_01_1 = {4c 61 72 65 77 69 62 69 66 61 } //1 Larewibifa
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}