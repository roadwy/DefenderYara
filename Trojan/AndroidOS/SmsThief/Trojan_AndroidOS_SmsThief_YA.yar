
rule Trojan_AndroidOS_SmsThief_YA{
	meta:
		description = "Trojan:AndroidOS/SmsThief.YA,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 55 72 6c 57 69 74 68 53 79 73 74 65 6d 4c 61 6e 67 75 61 67 65 } //2 loadUrlWithSystemLanguage
		$a_01_1 = {67 65 74 44 6f 6d 61 69 6e 2e 70 68 70 3f 73 72 76 63 3d } //2 getDomain.php?srvc=
		$a_01_2 = {73 6d 73 72 65 63 69 76 65 72 2e 67 34 63 74 73 6e 65 6f 67 7a 6d 66 37 6e 64 72 78 7a 6c 64 38 67 66 65 77 65 62 71 32 30 65 66 32 65 2e 6f 72 67 } //2 smsreciver.g4ctsneogzmf7ndrxzld8gfewebq20ef2e.org
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}