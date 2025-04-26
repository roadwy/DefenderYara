
rule Trojan_AndroidOS_Fakeapp_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 65 76 61 70 70 67 72 65 65 6e 2e 61 64 73 2e 7a 75 6d 6f 74 75 2e 78 79 7a } //1 revappgreen.ads.zumotu.xyz
		$a_00_1 = {6e 65 77 2e 78 79 7a 2f 3f 76 3d 61 67 } //1 new.xyz/?v=ag
		$a_00_2 = {73 6d 73 2e 6d 79 73 6d 73 70 61 6e 65 6c 2e 78 79 7a } //1 sms.mysmspanel.xyz
		$a_01_3 = {67 65 74 48 69 64 65 41 70 70 49 63 6f 6e } //1 getHideAppIcon
		$a_01_4 = {5a 75 6d 6f 74 75 46 61 63 74 6f 72 79 } //1 ZumotuFactory
		$a_00_5 = {70 68 6f 6e 65 2e 6d 79 73 6d 73 70 61 6e 65 6c } //1 phone.mysmspanel
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}