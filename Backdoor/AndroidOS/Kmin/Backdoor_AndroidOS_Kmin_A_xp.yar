
rule Backdoor_AndroidOS_Kmin_A_xp{
	meta:
		description = "Backdoor:AndroidOS/Kmin.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 6a 78 2f 72 65 73 2e 61 70 6b } //1 /jx/res.apk
		$a_00_1 = {2f 6a 78 2f 75 70 64 61 74 65 2e 61 70 6b } //1 /jx/update.apk
		$a_00_2 = {4c 63 6f 6d 2f 6a 78 2f 61 64 2f 42 6f 6f 74 53 6d 73 52 65 63 65 69 76 65 72 53 65 72 76 69 63 65 24 53 6d 73 52 65 63 65 69 76 65 72 } //1 Lcom/jx/ad/BootSmsReceiverService$SmsReceiver
		$a_00_3 = {63 6f 6d 2e 6a 78 2e 61 64 2e 41 44 53 65 72 76 69 63 65 2e 52 75 6e } //1 com.jx.ad.ADService.Run
		$a_00_4 = {48 61 73 49 6e 73 74 61 6c 6c 39 31 70 61 6e 64 61 } //1 HasInstall91panda
		$a_00_5 = {2f 2f 73 75 2e 35 6b 33 67 2e 63 6f 6d 2f 70 6f 72 74 61 6c 2f 6d 2f 63 35 2f 30 2e 61 73 68 78 } //1 //su.5k3g.com/portal/m/c5/0.ashx
		$a_00_6 = {2f 2f 77 77 77 2e 35 6a 35 6c 2e 63 6f 6d 2f 54 68 65 6d 65 44 6f 77 6e 65 72 2f 39 31 70 61 6e 64 61 68 6f 6d 65 32 2e 61 70 6b } //1 //www.5j5l.com/ThemeDowner/91pandahome2.apk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}