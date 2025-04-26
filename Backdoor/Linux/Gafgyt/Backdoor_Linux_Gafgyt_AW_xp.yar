
rule Backdoor_Linux_Gafgyt_AW_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AW!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 } //2 /bin/busybox chmod 777
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_2 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_00_3 = {33 32 6d 53 74 61 72 74 69 6e 67 20 53 63 61 6e 6e 65 72 } //1 32mStarting Scanner
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}