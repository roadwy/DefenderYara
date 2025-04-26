
rule Trojan_BAT_CryptInject_MBEO_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 67 68 68 66 67 73 66 66 66 64 64 64 73 68 66 64 61 73 64 66 68 } //1 fghhfgsfffdddshfdasdfh
		$a_01_1 = {73 67 66 68 6a 66 66 67 64 72 68 64 66 64 68 66 66 61 64 66 73 66 73 73 63 66 64 62 } //1 sgfhjffgdrhdfdhffadfsfsscfdb
		$a_01_2 = {64 6a 66 66 66 61 66 63 66 64 73 73 66 6b 66 68 67 6a } //1 djfffafcfdssfkfhgj
		$a_01_3 = {66 66 63 68 6b 66 64 61 66 68 66 6a } //1 ffchkfdafhfj
		$a_01_4 = {73 67 66 6a 68 6a 66 66 67 72 66 68 64 64 66 68 66 66 61 64 66 73 66 73 73 63 66 67 64 62 } //1 sgfjhjffgrfhddfhffadfsfsscfgdb
		$a_01_5 = {68 64 66 66 68 68 66 68 64 67 67 66 68 64 66 64 66 68 64 6a 66 68 64 61 73 66 66 66 66 6b 64 66 } //1 hdffhhfhdggfhdfdfhdjfhdasffffkdf
		$a_01_6 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}