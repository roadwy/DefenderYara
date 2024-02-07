
rule Backdoor_Linux_Gafgyt_AS_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 4c 4d 41 4f } //01 00  /bin/busybox LMAO
		$a_01_1 = {2f 64 65 76 2f 6e 65 74 73 6c 69 6e 6b 2f } //01 00  /dev/netslink/
		$a_01_2 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00  npxXoudifFeEgGaACScs
		$a_00_3 = {8c 7f 00 00 } //04 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Gafgyt_AS_xp_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.AS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 51 5a 75 51 5a 73 51 5a 79 51 5a 62 51 5a 6f 51 5a 78 } //01 00  bQZuQZsQZyQZbQZoQZx
		$a_00_1 = {2f 51 5a 64 51 5a 65 51 5a 76 51 5a 2f 51 5a 6e 51 5a 65 51 5a 74 51 5a 73 51 5a 6c 51 5a 69 51 5a 6e 51 5a 6b 51 5a 2f } //01 00  /QZdQZeQZvQZ/QZnQZeQZtQZsQZlQZiQZnQZkQZ/
		$a_00_2 = {4b 51 5a 49 51 5a 4c 51 5a 4c } //01 00  KQZIQZLQZL
		$a_00_3 = {55 51 5a 44 51 5a 50 } //01 00  UQZDQZP
		$a_00_4 = {4c 51 5a 49 51 5a 4c 51 5a 42 51 5a 49 51 5a 54 51 5a 43 51 5a 48 } //00 00  LQZIQZLQZBQZIQZTQZCQZH
	condition:
		any of ($a_*)
 
}