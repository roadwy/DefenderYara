
rule Trojan_Win32_Foinmer_A{
	meta:
		description = "Trojan:Win32/Foinmer.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 } //1
		$a_01_1 = {25 73 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 25 73 5c 65 78 74 65 6e 73 69 6f 6e 73 2e 72 64 66 } //1 %s\Mozilla\Firefox\%s\extensions.rdf
		$a_01_2 = {76 61 72 20 69 6e 5f 68 6f 73 74 73 20 3d 20 7b 27 6d 79 2e 6d 61 69 6c 2e 72 75 27 20 3a } //1 var in_hosts = {'my.mail.ru' :
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}