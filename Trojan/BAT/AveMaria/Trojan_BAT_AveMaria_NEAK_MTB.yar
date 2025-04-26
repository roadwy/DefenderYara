
rule Trojan_BAT_AveMaria_NEAK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //5 aR3nbf8dQp2feLmk31
		$a_01_1 = {4b 44 69 6b 4d 58 65 77 43 49 } //5 KDikMXewCI
		$a_01_2 = {45 6e 72 69 63 68 20 47 61 72 64 65 6e 20 53 65 72 76 69 63 65 73 } //3 Enrich Garden Services
		$a_01_3 = {6e 00 67 00 20 00 74 00 72 00 6f 00 6e 00 67 00 20 00 6b 00 68 00 6f 00 21 00 28 00 } //3 ng trong kho!(
		$a_01_4 = {44 61 79 53 74 61 72 74 } //3 DayStart
		$a_01_5 = {73 65 74 5f 43 68 65 63 6b 65 64 } //3 set_Checked
		$a_01_6 = {46 00 69 00 6e 00 64 00 53 00 74 00 61 00 66 00 66 00 42 00 79 00 53 00 70 00 65 00 6c 00 6c 00 73 00 } //2 FindStaffBySpells
		$a_01_7 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1) >=25
 
}