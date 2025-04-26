
rule Backdoor_Linux_Gafgyt_T_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.T!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0d 00 00 "
		
	strings :
		$a_00_0 = {66 61 6b 65 5f 72 65 73 6f 6c 76 65 5f 63 6e 63 5f 74 68 69 6e 67 } //1 fake_resolve_cnc_thing
		$a_00_1 = {53 65 6e 64 48 54 54 50 } //1 SendHTTP
		$a_00_2 = {73 65 6e 64 53 54 44 20 } //1 sendSTD 
		$a_00_3 = {63 6e 63 5f 6d 69 67 72 61 74 65 } //1 cnc_migrate
		$a_00_4 = {63 6e 63 69 6e 70 75 74 } //1 cncinput
		$a_00_5 = {5b 42 4f 54 5d 20 50 49 4e 47 20 66 72 6f 6d 20 25 73 } //1 [BOT] PING from %s
		$a_00_6 = {73 65 6e 64 5f 61 74 74 61 63 6b 73 } //1 send_attacks
		$a_00_7 = {4e 69 47 47 65 52 36 39 78 64 } //1 NiGGeR69xd
		$a_00_8 = {6b 69 6c 6c 69 6e 67 20 70 69 64 3a 20 25 64 } //1 killing pid: %d
		$a_00_9 = {76 73 74 61 72 63 61 6d 32 30 31 35 } //1 vstarcam2015
		$a_00_10 = {70 61 35 35 77 30 72 64 } //1 pa55w0rd
		$a_00_11 = {73 65 72 76 69 63 65 20 69 70 74 61 62 6c 65 73 20 73 74 6f 70 } //1 service iptables stop
		$a_00_12 = {78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 xXoudifFeEgGaACScs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=3
 
}