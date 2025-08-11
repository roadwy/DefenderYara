
rule Trojan_BAT_Heracles_MBZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2c 05 16 13 04 de 32 07 08 03 03 8e 69 12 03 } //2
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_2 = {43 6f 72 72 75 70 74 65 64 20 70 61 79 6c 6f 61 64 } //1 Corrupted payload
		$a_01_3 = {57 61 66 66 6c 65 44 65 63 6f 64 65 } //1 WaffleDecode
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}