
rule Backdoor_Linux_Mirai_be_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.be!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 67 20 2d 6c 20 64 76 72 48 65 6c 70 65 72 } //02 00  /bin/busybox tftp -g -l dvrHelper
		$a_00_1 = {6d 69 72 61 69 2e 61 72 6d } //01 00  mirai.arm
		$a_00_2 = {63 68 6d 6f 64 20 2b 78 20 64 76 72 48 65 6c 70 65 72 3b 20 2e 2f 64 76 72 48 65 6c 70 65 72 } //00 00  chmod +x dvrHelper; ./dvrHelper
	condition:
		any of ($a_*)
 
}