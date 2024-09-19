
rule Trojan_BAT_Phemedrone_APH_MTB{
	meta:
		description = "Trojan:BAT/Phemedrone.APH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 1c 00 06 07 03 07 91 04 07 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 00 07 17 58 } //2
		$a_01_1 = {44 65 62 75 67 5c 50 68 65 6d 65 64 72 6f 6e 65 2d 53 74 65 61 6c 65 72 2e 70 64 62 } //1 Debug\Phemedrone-Stealer.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Phemedrone_APH_MTB_2{
	meta:
		description = "Trojan:BAT/Phemedrone.APH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 0b 2b 23 11 0a 11 0b 91 13 0c 00 11 09 12 0c 72 00 0e 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 0b 17 58 13 0b 11 0b 11 0a 8e 69 } //2
		$a_01_1 = {6d 00 75 00 72 00 64 00 65 00 72 00 6f 00 75 00 73 00 61 00 74 00 74 00 61 00 63 00 6b 00 2e 00 78 00 79 00 7a 00 } //1 murderousattack.xyz
		$a_01_2 = {50 00 68 00 65 00 6d 00 65 00 64 00 72 00 6f 00 6e 00 65 00 2d 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Phemedrone-Stealer.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}