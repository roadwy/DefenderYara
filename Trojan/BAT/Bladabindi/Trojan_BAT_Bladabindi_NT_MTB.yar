
rule Trojan_BAT_Bladabindi_NT_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {37 31 30 35 66 63 35 64 2d 39 64 32 39 2d 34 65 37 33 2d 61 63 38 31 2d 32 64 61 31 39 36 32 62 62 39 30 39 } //2 7105fc5d-9d29-4e73-ac81-2da1962bb909
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_81_2 = {61 75 64 61 63 69 74 79 5f 77 69 6e } //1 audacity_win
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}