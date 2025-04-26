
rule Trojan_BAT_FormBook_NZM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 16 02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 1b 00 00 06 58 54 2a } //2
		$a_81_1 = {32 61 34 39 34 37 64 65 2d 37 37 33 34 2d 34 39 61 31 2d 39 66 63 30 2d 39 34 35 61 61 30 35 35 61 66 34 62 } //1 2a4947de-7734-49a1-9fc0-945aa055af4b
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}