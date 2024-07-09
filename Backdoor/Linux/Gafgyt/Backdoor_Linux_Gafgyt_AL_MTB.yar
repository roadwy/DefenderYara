
rule Backdoor_Linux_Gafgyt_AL_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 74 6d 70 3b 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 69 6e 66 65 63 74 20 2d 4f } //2
		$a_00_1 = {6a 65 53 6a 61 78 3b 20 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 6a 65 53 6a 61 78 3b 20 73 68 20 2f 74 6d 70 2f 6a 65 53 6a 61 78 } //1 jeSjax; busybox chmod 777 jeSjax; sh /tmp/jeSjax
		$a_00_2 = {53 54 4f 50 50 49 4e 47 20 54 45 4c 4e 45 54 20 53 43 41 4e 4e 45 52 } //1 STOPPING TELNET SCANNER
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}