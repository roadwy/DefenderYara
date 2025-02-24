
rule Trojan_AndroidOS_Mamont_G{
	meta:
		description = "Trojan:AndroidOS/Mamont.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 57 45 4c 20 47 45 54 20 42 41 4c } //2 PROWEL GET BAL
		$a_01_1 = {73 65 6e 64 73 6d 73 2f 54 46 41 63 74 69 76 69 74 79 } //2 sendsms/TFActivity
		$a_01_2 = {43 41 52 44 32 53 49 4d 53 42 45 52 } //2 CARD2SIMSBER
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}