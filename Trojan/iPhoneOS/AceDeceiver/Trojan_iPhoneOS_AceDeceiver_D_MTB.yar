
rule Trojan_iPhoneOS_AceDeceiver_D_MTB{
	meta:
		description = "Trojan:iPhoneOS/AceDeceiver.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 6f 73 33 2e 75 70 64 61 74 65 2e 69 34 2e 63 6e 2f 75 70 64 61 74 65 41 70 70 51 75 65 72 79 2e 78 68 74 6d 6c 3f 25 40 26 69 73 41 75 74 68 3d 25 40 26 63 69 64 3d 25 40 26 69 73 6a 61 69 6c 3d 25 40 26 74 6f 6f 6c 76 65 72 73 69 6f 6e 3d 25 40 } //2 ios3.update.i4.cn/updateAppQuery.xhtml?%@&isAuth=%@&cid=%@&isjail=%@&toolversion=%@
		$a_00_1 = {48 69 64 65 73 57 68 65 6e 53 74 6f 70 70 65 64 3a } //1 HidesWhenStopped:
		$a_00_2 = {6d 65 6d 62 65 72 5f 73 61 76 65 4c 6f 67 69 6e 49 6e 66 6f 2e 61 63 74 69 6f 6e } //1 member_saveLoginInfo.action
		$a_00_3 = {63 6f 6d 2e 74 65 69 72 6f 6e 2e 70 70 73 79 6e 63 } //1 com.teiron.ppsync
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}