
rule Backdoor_Linux_Mirai_AO_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AO!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 63 6f 6e 66 69 67 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66 } //1 /etc/config/resolv.conf
		$a_01_1 = {38 39 36 39 38 37 36 68 6a 6b 67 68 62 6c 6b } //1 8969876hjkghblk
		$a_01_2 = {67 68 64 75 67 66 66 79 74 73 64 79 74 } //1 ghdugffytsdyt
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}