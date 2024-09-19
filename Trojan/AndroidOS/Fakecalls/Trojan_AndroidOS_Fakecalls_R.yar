
rule Trojan_AndroidOS_Fakecalls_R{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.R,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 57 56 6c 59 57 49 72 50 6a 35 31 66 6d 5a 5f 50 32 4a 34 66 33 6c 77 66 7a 78 7a 63 48 39 36 50 33 4a 2d 66 44 35 35 5a 48 6c } //1 eWVlYWIrPj51fmZ_P2J4f3lwfzxzcH96P3J-fD55ZHl
		$a_01_1 = {2f 61 70 69 2f 61 70 70 6c 69 6e 6b 2f 72 65 71 75 65 73 74 4d 61 69 6e 43 61 6c } //1 /api/applink/requestMainCal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}