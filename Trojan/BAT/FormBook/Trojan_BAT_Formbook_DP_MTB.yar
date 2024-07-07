
rule Trojan_BAT_Formbook_DP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 61 31 36 61 62 62 62 34 2d 39 38 35 62 2d 34 64 62 32 2d 61 38 30 63 2d 32 31 32 36 38 62 32 36 63 37 33 64 } //1 $a16abbb4-985b-4db2-a80c-21268b26c73d
		$a_81_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_3 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_81_4 = {53 74 6f 72 6d 4b 69 74 74 79 } //1 StormKitty
		$a_81_5 = {4c 69 6d 65 72 42 6f 79 } //1 LimerBoy
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}