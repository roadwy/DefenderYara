
rule Trojan_BAT_Remcos_AYDA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AYDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0e 05 1f 7b 61 20 ff 00 00 00 5f 20 c8 01 00 00 58 20 00 01 00 00 5e 26 05 03 04 03 91 0e 04 0e 05 95 61 d2 9c 2a } //4
		$a_01_1 = {48 00 45 00 48 00 5a 00 36 00 47 00 37 00 38 00 47 00 37 00 42 00 34 00 47 00 46 00 44 00 38 00 45 00 45 00 38 00 41 00 37 00 39 00 } //1 HEHZ6G78G7B4GFD8EE8A79
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}