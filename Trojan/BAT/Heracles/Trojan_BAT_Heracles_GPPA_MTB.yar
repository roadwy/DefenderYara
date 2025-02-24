
rule Trojan_BAT_Heracles_GPPA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {5a 58 4e 7a 4b 51 30 4b 4a 47 51 75 55 6d 56 68 5a 43 67 6b 59 69 77 67 4d 43 77 67 4f 44 4d 35 } //3 ZXNzKQ0KJGQuUmVhZCgkYiwgMCwgODM5
		$a_81_1 = {55 35 31 62 47 77 4e 43 6c 74 53 5a 57 5a 73 5a 57 4e 30 61 57 39 75 4c 6b 46 7a 63 32 56 74 59 6d 78 } //2 U51bGwNCltSZWZsZWN0aW9uLkFzc2VtYmx
		$a_81_2 = {43 6c 74 7a 64 48 56 69 4c 6c 42 79 62 32 64 79 59 57 31 64 4f 6a 70 4e 59 57 6c 75 } //1 CltzdHViLlByb2dyYW1dOjpNYWlu
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}