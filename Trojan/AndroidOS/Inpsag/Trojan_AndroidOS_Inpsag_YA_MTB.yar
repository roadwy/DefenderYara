
rule Trojan_AndroidOS_Inpsag_YA_MTB{
	meta:
		description = "Trojan:AndroidOS/Inpsag.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 46 61 6b 65 50 61 67 65 2e 66 69 6e } //1 com.FakePage.fin
		$a_00_1 = {63 6f 6d 2e 61 64 72 74 2e 43 4f 4e 4e 45 43 54 } //1 com.adrt.CONNECT
		$a_00_2 = {63 6f 6d 2e 61 64 72 74 2e 42 52 45 41 4b 50 4f 49 4e 54 5f 48 49 54 } //1 com.adrt.BREAKPOINT_HIT
		$a_00_3 = {63 6f 6d 2e 61 64 72 74 2e 4c 4f 47 43 41 54 5f 45 4e 54 52 49 45 53 } //1 com.adrt.LOGCAT_ENTRIES
		$a_00_4 = {52 55 68 46 53 45 5a 4a 56 55 56 4a 52 6b 56 47 52 46 4e 42 } //1 RUhFSEZJVUVJRkVGRFNB
		$a_00_5 = {53 44 79 6b 4f 36 52 41 59 33 6a 49 75 38 53 74 34 } //1 SDykO6RAY3jIu8St4
		$a_00_6 = {61 63 63 6f 75 6e 74 73 2f 70 61 73 73 77 6f 72 64 2f 72 65 73 65 74 } //1 accounts/password/reset
		$a_00_7 = {4f 41 45 6d 59 6f 62 44 39 30 69 35 } //1 OAEmYobD90i5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}