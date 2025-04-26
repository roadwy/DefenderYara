
rule DDoS_Linux_Triddy_A_xp{
	meta:
		description = "DDoS:Linux/Triddy.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 52 55 4d 50 20 49 53 20 44 41 44 44 59 } //2 TRUMP IS DADDY
		$a_01_1 = {77 65 62 66 75 63 6b } //1 webfuck
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}