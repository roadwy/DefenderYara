
rule Trojan_BAT_Remcos_AOBV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 07 06 6f } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}