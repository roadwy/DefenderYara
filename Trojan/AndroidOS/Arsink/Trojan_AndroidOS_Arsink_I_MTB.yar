
rule Trojan_AndroidOS_Arsink_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 44 65 61 74 68 52 61 74 } //1 com/DeathRat
		$a_01_1 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 _getAllContacts
		$a_01_2 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //1 getAllCallsHistoty
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}