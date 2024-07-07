
rule Backdoor_AndroidOS_Ztorg_A_xp{
	meta:
		description = "Backdoor:AndroidOS/Ztorg.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 41 70 70 43 68 6d 6f 64 } //1 checkAppChmod
		$a_01_1 = {63 68 65 63 6b 49 6e 73 74 61 6c 6c 52 65 63 6f 76 65 72 79 45 74 63 } //1 checkInstallRecoveryEtc
		$a_01_2 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 2e 63 61 74 72 2e 61 70 6b } //1 /data/local/tmp/.catr.apk
		$a_01_3 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 62 75 73 79 62 6f 78 } //1 /data/local/tmp/busybox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}