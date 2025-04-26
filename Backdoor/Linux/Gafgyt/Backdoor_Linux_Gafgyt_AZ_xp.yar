
rule Backdoor_Linux_Gafgyt_AZ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AZ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 6b 55 78 7a 76 75 74 73 72 71 70 5f 6e 6d 2d 69 68 67 66 46 43 63 62 61 } //1 wkUxzvutsrqp_nm-ihgfFCcba
		$a_00_1 = {73 65 6e 64 69 6e 67 20 6b 69 6c 6c 20 72 65 71 75 65 73 74 } //1 sending kill request
		$a_00_2 = {5b 6b 69 6c 6c 65 72 5d 20 66 69 6e 64 69 6e 67 20 61 6e 64 20 6b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 65 73 20 68 6f 6c 64 69 6e 67 20 70 6f 72 74 } //1 [killer] finding and killing processes holding port
		$a_00_3 = {5b 61 74 74 61 63 6b 5d 20 73 74 61 72 74 69 6e 67 20 61 74 74 61 63 6b } //1 [attack] starting attack
		$a_00_4 = {2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } //1 /proc/cpuinfo
		$a_01_5 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}