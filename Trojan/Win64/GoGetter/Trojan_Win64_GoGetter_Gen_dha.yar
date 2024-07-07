
rule Trojan_Win64_GoGetter_Gen_dha{
	meta:
		description = "Trojan:Win64/GoGetter.Gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_43_0 = {1f 40 00 48 39 cb 75 11 48 89 c3 48 90 01 04 e8 90 01 04 84 c0 75 9e 90 00 64 } //100
		$a_c6_1 = {24 1f 03 48 8b 94 24 90 01 01 01 00 00 48 8b 90 01 01 ff 90 00 00 00 5d 04 00 00 05 0c 05 80 5c 26 00 00 06 0c 05 80 00 00 01 00 08 00 10 00 ad 41 50 68 69 73 68 2e 45 41 53 4d 21 4d 54 42 00 00 01 40 } //5888
	condition:
		((#a_43_0  & 1)*100+(#a_c6_1  & 1)*5888) >=200
 
}