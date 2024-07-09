
rule Trojan_BAT_Nanocore_AAFA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //3
		$a_01_1 = {4d 00 61 00 69 00 6e 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //1 Main_Project
		$a_01_2 = {49 00 53 00 44 00 6e 00 6b 00 52 00 4a 00 5a 00 67 00 6b 00 42 00 35 00 42 00 46 00 33 00 4e 00 } //1 ISDnkRJZgkB5BF3N
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}