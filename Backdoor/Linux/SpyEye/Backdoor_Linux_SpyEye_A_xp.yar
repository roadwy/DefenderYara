
rule Backdoor_Linux_SpyEye_A_xp{
	meta:
		description = "Backdoor:Linux/SpyEye.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 63 68 6f 20 22 2f 63 6f 72 65 66 69 6c 65 2f 63 6f 72 65 2d 25 65 2d 25 70 2d 25 74 22 20 3e 20 2f 70 72 6f 63 2f 73 79 73 2f 6b 65 72 6e 65 6c 2f 63 6f 72 65 5f 70 61 74 74 65 72 6e } //01 00  echo "/corefile/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
		$a_00_1 = {2f 6c 69 62 2f 35 64 35 37 30 36 38 36 2d 33 37 65 65 2d 31 31 65 32 2d 62 32 32 38 2d 30 30 30 63 32 39 32 63 62 36 35 63 } //01 00  /lib/5d570686-37ee-11e2-b228-000c292cb65c
		$a_00_2 = {2f 74 6d 70 2f 69 74 6b 6c 6f 67 2e 74 78 74 } //01 00  /tmp/itklog.txt
		$a_00_3 = {6d 6b 64 69 72 20 2f 63 6f 72 65 66 69 6c 65 } //00 00  mkdir /corefile
	condition:
		any of ($a_*)
 
}