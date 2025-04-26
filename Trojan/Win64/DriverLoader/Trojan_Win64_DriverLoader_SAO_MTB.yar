
rule Trojan_Win64_DriverLoader_SAO_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.SAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 57 6d 69 50 72 76 53 45 2a 20 2f 66 20 2f 74 } //2 taskkill /im WmiPrvSE* /f /t
		$a_01_1 = {70 72 6f 74 65 63 74 65 64 20 62 79 20 64 69 77 6e 65 73 73 20 70 72 6f 74 65 63 74 69 6f 6e } //2 protected by diwness protection
		$a_01_2 = {52 00 61 00 69 00 64 00 50 00 6f 00 72 00 74 00 } //2 RaidPort
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}