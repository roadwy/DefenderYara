
rule Backdoor_Linux_Gafgyt_BN_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BN!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a [0-28] 2f 66 79 66 61 2e 73 68 } //2
		$a_01_1 = {2f 75 73 72 2f 73 62 69 6e 73 2f 64 72 6f 70 62 65 61 72 } //1 /usr/sbins/dropbear
		$a_01_2 = {52 4d 42 55 53 59 } //1 RMBUSY
		$a_01_3 = {42 75 73 79 42 6f 78 } //1 BusyBox
		$a_01_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}