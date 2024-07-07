
rule Virus_Win32_Expiro_gen_D{
	meta:
		description = "Virus:Win32/Expiro.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3c 65 74 14 3c 79 74 10 3c 75 74 0c 3c 69 74 08 3c 6f 74 04 3c 61 75 04 } //1
		$a_00_1 = {8b 45 d8 8a 84 05 d9 fe ff ff 3c 61 7e 11 3c 7a 7d 0d 8b 45 d8 8d 84 05 d9 fe ff ff 80 28 20 ff 45 d8 8b 45 d8 0f be 84 05 d9 fe ff ff } //1
		$a_02_2 = {0f b6 45 10 39 c7 72 90 01 01 8a 04 3e 3c 2f 74 90 01 01 3c 2e 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}