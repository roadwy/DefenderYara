
rule Backdoor_Linux_Gafgyt_CA_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CA!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 55 49 43 49 44 45 42 4f 59 24 } //1 $UICIDEBOY$
		$a_01_1 = {6b 69 6c 6c 65 64 20 70 69 64 } //1 killed pid
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_01_4 = {6d 48 6f 49 4a 50 71 47 52 53 54 55 56 57 58 4c } //1 mHoIJPqGRSTUVWXL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}