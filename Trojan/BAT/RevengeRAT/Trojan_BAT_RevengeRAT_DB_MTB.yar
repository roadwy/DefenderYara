
rule Trojan_BAT_RevengeRAT_DB_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0a 13 04 17 13 05 2b 41 08 07 33 02 17 0c 03 08 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 09 02 11 05 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 06 07 d8 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 04 31 b9 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}