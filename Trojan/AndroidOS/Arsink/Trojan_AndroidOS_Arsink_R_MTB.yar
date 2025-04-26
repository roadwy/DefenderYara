
rule Trojan_AndroidOS_Arsink_R_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 20 48 61 63 6b 20 44 61 74 61 } //1 Phone Hack Data
		$a_01_1 = {67 65 74 41 6c 6c 53 6d 73 } //1 getAllSms
		$a_01_2 = {54 6f 6b 65 6e 2e 74 78 74 } //1 Token.txt
		$a_01_3 = {68 61 68 61 5f 6c 6f 6c } //1 haha_lol
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}