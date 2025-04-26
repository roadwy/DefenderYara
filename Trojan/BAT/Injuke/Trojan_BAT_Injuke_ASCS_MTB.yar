
rule Trojan_BAT_Injuke_ASCS_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ASCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 8e 69 17 da 13 0f 16 13 10 2b 1b 11 07 11 06 11 10 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 df } //1
		$a_01_1 = {44 00 4b 00 4a 00 41 00 59 00 48 00 47 00 44 00 4b 00 49 00 55 00 48 00 20 00 4b 00 48 00 4a 00 47 00 44 00 41 00 47 00 44 00 4a 00 4b 00 41 00 48 00 } //1 DKJAYHGDKIUH KHJGDAGDJKAH
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}