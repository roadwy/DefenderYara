
rule Trojan_MacOS_Amos_Q_MTB{
	meta:
		description = "Trojan:MacOS/Amos.Q!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 49 89 fe bf 10 00 00 00 e8 90 45 00 00 48 89 c3 48 89 c7 4c 89 f6 e8 2e 00 00 00 48 8b 35 5f 79 00 00 48 8b 15 08 79 00 00 48 89 df e8 90 45 00 00 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 fb e8 4a 44 00 00 48 8b 05 53 79 00 00 48 83 c0 10 48 89 03 48 83 c4 08 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}