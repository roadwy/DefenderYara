
rule Trojan_BAT_Zilla_ZLY_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 25 20 02 00 00 00 6f ?? 00 00 0a 25 fe 09 01 00 28 ?? 00 00 0a fe 09 02 00 28 ?? 00 00 0a 6f ?? 00 00 0a 25 fe 0c 00 00 20 00 00 00 00 fe 0c 00 00 8e 69 6f ?? 00 00 0a fe 0e 01 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}