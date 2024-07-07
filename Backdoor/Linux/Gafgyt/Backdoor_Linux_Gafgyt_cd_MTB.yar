
rule Backdoor_Linux_Gafgyt_cd_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.cd!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 65 72 20 73 74 61 72 74 65 64 } //1 killer started
		$a_00_1 = {68 62 6f 74 20 70 72 6f 63 20 73 74 61 72 74 69 6e 67 } //1 hbot proc starting
		$a_00_2 = {5b 74 65 6c 5d 20 6c 6f 67 69 6e 20 61 74 74 65 6d 70 74 20 5b 25 73 3a 32 33 20 25 73 3a 25 73 5d } //1 [tel] login attempt [%s:23 %s:%s]
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 48 42 4f 54 } //1 /bin/busybox HBOT
		$a_00_4 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2e 64 72 6f 70 70 65 72 } //1 /bin/busybox chmod 777 .dropper
		$a_00_5 = {5b 74 65 6c 5d 20 64 72 6f 70 70 65 72 20 65 78 65 63 75 74 65 64 } //1 [tel] dropper executed
		$a_00_6 = {68 74 74 70 5f 61 74 74 61 63 6b } //1 http_attack
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}