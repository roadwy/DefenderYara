
rule Trojan_BAT_Lazy_NJ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 } //5
		$a_81_1 = {47 65 74 4d 52 41 43 47 61 6d 65 } //2 GetMRACGame
		$a_81_2 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 } //2 $$method0x600
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=10
 
}