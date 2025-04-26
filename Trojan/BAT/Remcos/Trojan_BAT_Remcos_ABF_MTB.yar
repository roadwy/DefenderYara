
rule Trojan_BAT_Remcos_ABF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 02 03 73 ?? ?? ?? 0a 8c ?? ?? ?? 01 13 05 2b 00 11 05 2a } //5
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}