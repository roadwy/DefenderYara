
rule Trojan_BAT_Grotseento_A{
	meta:
		description = "Trojan:BAT/Grotseento.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 61 79 6e 61 6b 6c 69 6e 6b 69 00 70 72 65 6c 69 6b 61 79 6e 61 6b 6b 6f 64 75 00 6d 61 6e 69 64 65 67 65 72 00 63 72 78 6b 6f 64 75 00 61 6e 61 68 74 61 72 } //1
		$a_01_1 = {6b 6f 79 76 65 72 67 69 74 73 69 6e 00 63 72 6f 6d 64 6f 63 75 6d 65 6e 74 00 63 72 6f 6d 64 65 66 65 61 75 6c 74 00 63 72 78 79 6f 6c } //1
		$a_01_2 = {66 65 64 61 68 61 62 65 72 2e 63 6f 6d 2f 22 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}