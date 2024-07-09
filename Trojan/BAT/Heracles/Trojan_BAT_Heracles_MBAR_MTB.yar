
rule Trojan_BAT_Heracles_MBAR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 02 6f ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d 07 6f ?? 00 00 0a 09 2a } //1
		$a_01_1 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //1 payload.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}