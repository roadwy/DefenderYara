
rule Trojan_AndroidOS_Oscorp_A{
	meta:
		description = "Trojan:AndroidOS/Oscorp.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 49 44 44 45 4e 66 69 72 73 74 54 69 6d 65 } //1 HIDDENfirstTime
		$a_00_1 = {66 75 63 6b } //1 fuck
		$a_00_2 = {63 6f 6d 2e 63 6f 73 6d 6f 73 2e 73 74 61 72 77 61 72 7a } //1 com.cosmos.starwarz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}