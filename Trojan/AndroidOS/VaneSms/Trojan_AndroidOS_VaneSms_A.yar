
rule Trojan_AndroidOS_VaneSms_A{
	meta:
		description = "Trojan:AndroidOS/VaneSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 68 6f 6e 65 2e 69 6e 64 65 78 4f 66 28 61 61 5b 69 5d 29 3d } //1 phone.indexOf(aa[i])=
		$a_01_1 = {24 45 76 61 6e 2e 42 61 63 6b 67 72 6f 75 6e 64 53 4d 53 2e 42 6f 6f 74 53 65 72 76 69 63 65 2e 63 6c 61 73 73 } //1 $Evan.BackgroundSMS.BootService.class
		$a_01_2 = {61 64 73 6d 73 2e 69 74 6f 64 6f 2e 63 6e 2f 52 65 70 6f 72 74 2f 53 65 70 6b 66 43 6f 6e 66 69 72 6d 2e 61 73 70 78 3f 73 70 69 64 3d } //1 adsms.itodo.cn/Report/SepkfConfirm.aspx?spid=
		$a_01_3 = {47 50 2e 48 61 72 65 43 6f 64 65 52 65 67 4e 75 6d 5b 74 5d 3d } //1 GP.HareCodeRegNum[t]=
		$a_01_4 = {49 73 53 65 70 43 68 61 6e 6e 65 6c 53 65 6e 64 65 64 3d } //1 IsSepChannelSended=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}