
rule Trojan_Win32_Zbot_EC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 8d 0c 06 8a c3 02 45 fc 32 01 32 45 f8 32 c3 88 01 85 db 75 04 34 02 88 01 } //10
		$a_81_1 = {74 6d 70 5c 77 68 65 72 65 2e 70 64 62 } //3 tmp\where.pdb
		$a_81_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //3 InternetOpenUrlA
		$a_81_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //3 InternetReadFile
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=16
 
}