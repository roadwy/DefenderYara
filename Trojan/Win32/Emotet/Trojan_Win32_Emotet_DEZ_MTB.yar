
rule Trojan_Win32_Emotet_DEZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 63 11 00 00 f7 f9 8b 84 24 ?? ?? ?? ?? 40 89 84 24 90 1b 00 8a 94 14 ?? ?? ?? ?? 30 54 03 ff } //1
		$a_81_1 = {69 65 71 59 6d 55 67 37 69 67 4c 6a 75 54 4a 4c 42 6a 44 39 52 53 67 31 57 42 61 71 6f 6e 61 4d 30 36 } //1 ieqYmUg7igLjuTJLBjD9RSg1WBaqonaM06
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}