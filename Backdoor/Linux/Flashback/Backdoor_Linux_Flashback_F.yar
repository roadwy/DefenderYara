
rule Backdoor_Linux_Flashback_F{
	meta:
		description = "Backdoor:Linux/Flashback.F,SIGNATURE_TYPE_MACHOHSTR_EXT,10 00 0f 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 2e 25 73 2e 73 6f } //01 00  %s.%s.so
		$a_01_1 = {25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 64 } //01 00  %s|%s|%s|%s|%s|%s|%d
		$a_01_2 = {25 73 20 22 25 73 25 73 25 73 22 20 25 73 20 22 25 73 } //01 00  %s "%s%s%s" %s "%s
		$a_01_3 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //01 00  IOPlatformUUID
		$a_01_4 = {73 79 73 63 74 6c 2e 70 72 6f 63 5f 63 70 75 74 79 70 65 } //06 00  sysctl.proc_cputype
		$a_01_5 = {64 46 64 31 6a 73 } //06 00  dFd1js
		$a_03_6 = {f7 d0 21 c2 81 90 01 01 80 80 80 80 74 90 01 01 89 90 01 01 c1 e8 10 f7 c2 80 80 00 00 0f 44 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}