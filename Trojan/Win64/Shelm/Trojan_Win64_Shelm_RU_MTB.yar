
rule Trojan_Win64_Shelm_RU_MTB{
	meta:
		description = "Trojan:Win64/Shelm.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 48 48 8d 85 20 02 00 00 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 c7 44 24 28 00 00 00 08 89 74 24 20 45 33 c9 45 33 c0 48 8d 95 a0 03 00 00 33 c9 ff 15 } //1
		$a_01_1 = {44 65 6c 20 2f 66 20 2f 71 20 22 25 73 22 } //1 Del /f /q "%s"
		$a_01_2 = {55 73 65 72 73 5c 73 53 73 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 54 65 73 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 54 65 73 74 2e 70 64 62 } //1 Users\sSs\source\repos\Test\x64\Release\Test.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}