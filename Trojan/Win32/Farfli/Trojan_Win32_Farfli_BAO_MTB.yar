
rule Trojan_Win32_Farfli_BAO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6d 67 63 61 63 68 65 2e 76 69 70 30 33 33 33 32 34 2e 78 79 7a } //01 00  imgcache.vip033324.xyz
		$a_01_1 = {38 37 2e 32 35 31 2e 74 78 74 } //01 00  87.251.txt
		$a_01_2 = {70 64 61 74 65 33 36 30 2e 64 61 74 } //01 00  pdate360.dat
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 54 68 75 6e 64 65 72 55 70 64 61 74 65 } //01 00  C:\ProgramData\ThunderUpdate
		$a_01_4 = {83 c4 08 6a 05 68 b4 51 40 00 68 0c 54 40 00 68 e8 51 40 00 68 ac 51 40 00 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}