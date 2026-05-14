
rule Trojan_BAT_MonikerLoader_AMK_MTB{
	meta:
		description = "Trojan:BAT/MonikerLoader.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {0c 16 0d 2b 19 07 09 91 1f 4d 58 13 04 11 04 1f 78 61 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 8e 69 } //3
		$a_01_1 = {0a 16 0b 2b 15 02 07 91 1f 4d 58 0c 08 1f 78 61 0c 06 07 08 d2 9c 07 17 58 0b 07 02 8e 69 } //2
		$a_01_2 = {53 45 52 56 49 43 45 5f 53 54 4f 50 50 45 44 } //1 SERVICE_STOPPED
		$a_01_3 = {53 45 52 56 49 43 45 5f 52 55 4e 4e 49 4e 47 } //1 SERVICE_RUNNING
		$a_01_4 = {53 45 52 56 49 43 45 5f 43 4f 4e 54 52 4f 4c 5f 53 54 4f 50 } //1 SERVICE_CONTROL_STOP
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}