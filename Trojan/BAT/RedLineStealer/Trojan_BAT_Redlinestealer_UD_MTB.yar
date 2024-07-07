
rule Trojan_BAT_Redlinestealer_UD_MTB{
	meta:
		description = "Trojan:BAT/Redlinestealer.UD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 69 70 2e 73 62 2f 69 70 } //api.ip.sb/ip  1
		$a_01_1 = {44 65 63 72 79 70 74 42 6c 6f 62 } //1 DecryptBlob
		$a_80_2 = {42 43 72 62 79 74 65 5b 5d 79 70 74 44 65 73 62 79 74 65 5b 5d 74 72 6f 79 4b 62 79 74 65 5b 5d 65 79 } //BCrbyte[]yptDesbyte[]troyKbyte[]ey  1
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_4 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 get_encrypted_key
		$a_80_5 = {52 6f 61 6d 69 6e 67 5c 54 52 65 70 6c 61 63 65 6f 6b 52 65 70 6c 61 63 65 65 6e 52 65 70 6c 61 63 65 73 2e 74 52 65 70 6c 61 63 65 78 74 } //Roaming\TReplaceokReplaceenReplaces.tReplacext  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}