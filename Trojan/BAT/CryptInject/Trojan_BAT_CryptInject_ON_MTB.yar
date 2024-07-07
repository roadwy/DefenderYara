
rule Trojan_BAT_CryptInject_ON_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.ON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 00 48 00 4f 00 50 00 5f 00 4f 00 50 00 45 00 4e 00 5f 00 4f 00 4e 00 4c 00 49 00 4e 00 45 00 5f 00 53 00 54 00 4f 00 52 00 45 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 32 00 34 00 33 00 39 00 } //1 SHOP_OPEN_ONLINE_STORE_ICON_192439
		$a_81_1 = {61 64 66 61 73 64 61 73 } //1 adfasdas
		$a_81_2 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //1 BitTreeDecoder
		$a_81_3 = {6d 5f 49 73 52 65 70 47 30 44 65 63 6f 64 65 72 73 } //1 m_IsRepG0Decoders
		$a_81_4 = {5f 73 6f 6c 69 64 } //1 _solid
		$a_81_5 = {53 65 74 44 69 63 74 69 6f 6e 61 72 79 53 69 7a 65 } //1 SetDictionarySize
		$a_81_6 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //1 DecodeWithMatchByte
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}