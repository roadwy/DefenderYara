
rule Trojan_BAT_ClipBanker_DY_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 41 00 52 00 4b 00 45 00 54 00 49 00 4e 00 47 00 5f 00 53 00 45 00 4f 00 5f 00 41 00 44 00 56 00 45 00 52 00 54 00 49 00 53 00 49 00 4e 00 47 00 5f 00 50 00 52 00 4f 00 4d 00 4f 00 54 00 49 00 4f 00 4e 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 32 00 34 00 33 00 32 00 } //1 MARKETING_SEO_ADVERTISING_PROMOTION_ICON_192432
		$a_81_1 = {30 6b 30 30 30 68 32 32 32 5d 37 37 36 4b } //1 0k000h222]776K
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_3 = {61 64 66 61 73 64 61 73 } //1 adfasdas
		$a_81_4 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //1 ResolveSignature
		$a_81_5 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //1 get_FullName
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_ClipBanker_DY_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 64 66 61 73 64 61 73 } //1 adfasdas
		$a_81_1 = {61 66 64 67 64 66 73 66 73 } //1 afdgdfsfs
		$a_81_2 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //1 ResolveSignature
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_4 = {6d 5f 44 69 63 74 69 6f 6e 61 72 79 53 69 7a 65 43 68 65 63 6b } //1 m_DictionarySizeCheck
		$a_01_5 = {41 00 44 00 44 00 5f 00 54 00 4f 00 5f 00 43 00 41 00 52 00 54 00 5f 00 4f 00 4e 00 4c 00 49 00 4e 00 45 00 5f 00 53 00 48 00 4f 00 50 00 50 00 49 00 4e 00 47 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 32 00 34 00 32 00 35 00 } //1 ADD_TO_CART_ONLINE_SHOPPING_ICON_192425
		$a_01_6 = {67 00 66 00 64 00 64 00 73 00 66 00 64 00 73 00 66 00 } //1 gfddsfdsf
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}