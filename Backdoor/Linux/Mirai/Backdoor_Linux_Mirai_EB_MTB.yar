
rule Backdoor_Linux_Mirai_EB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00  /bin/busybox
		$a_01_1 = {63 75 6e 64 69 2e 6d 36 38 6b } //01 00  cundi.m68k
		$a_01_2 = {61 6e 6b 6f 2d 61 70 70 2f 61 6e 6b 6f 73 61 6d 70 6c 65 20 5f 38 31 38 32 54 5f 31 31 30 34 } //01 00  anko-app/ankosample _8182T_1104
		$a_01_3 = {2f 72 6f 6f 74 2f 64 76 72 5f 67 75 69 2f } //00 00  /root/dvr_gui/
	condition:
		any of ($a_*)
 
}