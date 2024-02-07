
rule Backdoor_Linux_Gafgyt_CF_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CF!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 6b 69 6c 6c 20 2d 39 20 25 64 } //01 00  /bin/busybox kill -9 %d
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 61 74 20 2f 70 72 6f 63 2f 6d 6f 75 6e 74 73 } //01 00  /bin/busybox cat /proc/mounts
		$a_00_2 = {72 6d 20 2d 72 66 20 63 6d 73 67 75 61 72 64 20 75 70 6e 70 } //01 00  rm -rf cmsguard upnp
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 65 63 68 6f 20 2d 65 20 27 25 73 25 73 27 20 3e 20 25 73 2f 2e 6e 69 70 70 6f 6e } //00 00  /bin/busybox echo -e '%s%s' > %s/.nippon
	condition:
		any of ($a_*)
 
}