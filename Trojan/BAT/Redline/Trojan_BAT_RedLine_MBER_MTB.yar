
rule Trojan_BAT_RedLine_MBER_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 67 68 66 67 73 66 66 66 66 66 64 66 64 66 64 73 66 64 61 73 64 66 68 } //1 fghfgsfffffdfdfdsfdasdfh
		$a_01_1 = {73 67 66 68 6a 66 66 67 64 72 66 68 64 66 64 68 66 66 61 64 66 73 66 73 73 63 66 64 62 } //1 sgfhjffgdrfhdfdhffadfsfsscfdb
		$a_01_2 = {6a 66 66 66 66 66 66 73 64 67 6b 66 66 66 66 } //1 jffffffsdgkffff
		$a_01_3 = {68 64 66 66 68 68 66 68 64 67 67 66 68 64 66 64 66 68 64 6a 66 68 64 61 73 66 66 66 66 6b 64 66 } //1 hdffhhfhdggfhdfdfhdjfhdasffffkdf
		$a_01_4 = {6b 66 66 73 6a 67 67 66 66 66 68 } //1 kffsjggfffh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}