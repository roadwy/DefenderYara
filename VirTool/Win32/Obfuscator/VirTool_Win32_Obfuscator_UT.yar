
rule VirTool_Win32_Obfuscator_UT{
	meta:
		description = "VirTool:Win32/Obfuscator.UT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_10_0 = {c6 82 58 01 00 00 4b 8b 45 08 c6 80 59 01 00 00 65 8b 4d 08 c6 81 5a 01 00 00 72 8b 55 08 c6 82 5b 01 00 00 6e 8b 45 08 c6 80 5c 01 00 00 65 8b 4d 08 c6 81 5d 01 00 00 6c 8b 55 08 c6 82 5e 01 00 00 33 8b 45 08 c6 80 5f 01 00 00 32 8b 4d 08 c6 81 60 01 00 00 2e 8b 55 08 c6 82 61 01 00 00 64 8b 45 08 c6 80 62 01 00 00 6c 8b 4d 08 c6 81 63 01 00 00 6c } //1
		$a_10_1 = {c6 80 bc 00 00 00 5e 8b 4d 08 c6 81 bd 00 00 00 3a 8b 55 08 c6 82 be 00 00 00 72 8b 45 08 c6 80 bf 00 00 00 3a } //1
		$a_10_2 = {c6 42 7c 47 8b 45 08 c6 40 7d 65 8b 4d 08 c6 41 7e 74 8b 55 08 c6 42 7f 50 } //1
	condition:
		((#a_10_0  & 1)*1+(#a_10_1  & 1)*1+(#a_10_2  & 1)*1) >=3
 
}