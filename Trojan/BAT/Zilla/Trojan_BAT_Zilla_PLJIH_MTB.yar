
rule Trojan_BAT_Zilla_PLJIH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PLJIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 16 08 16 1e 28 ?? 00 00 0a 00 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 05 16 0e 04 8e 69 6f ?? 00 00 0a 13 04 de 16 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}