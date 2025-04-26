
rule Trojan_BAT_Remcos_AEOQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AEOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}