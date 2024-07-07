
rule Trojan_Win32_Emotet_DSL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8b cf 99 f7 f9 8b 45 90 01 01 83 4d fc ff 8a 8c 15 90 01 04 30 08 90 00 } //1
		$a_81_1 = {51 65 65 48 30 6a 77 39 61 72 48 4a 6d 6e 75 79 35 4a 71 55 6f 5a 59 77 32 77 5a 75 30 4a 74 71 49 49 48 } //1 QeeH0jw9arHJmnuy5JqUoZYw2wZu0JtqIIH
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}