
rule Backdoor_Linux_Mirai_K_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 61 72 6b 5f 6e 65 78 75 73 } //1 dark_nexus
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //1 /bin/busybox
		$a_00_2 = {73 77 69 74 63 68 6e 65 74 73 2e 6e 65 74 } //1 switchnets.net
		$a_00_3 = {74 68 69 63 63 6e 69 67 67 61 2e 6d 65 } //1 thiccnigga.me
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}