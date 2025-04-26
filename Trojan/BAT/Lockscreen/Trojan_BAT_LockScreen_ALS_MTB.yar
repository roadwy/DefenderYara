
rule Trojan_BAT_LockScreen_ALS_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.ALS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 04 11 05 14 28 ?? ?? ?? 0a 14 fe 01 13 09 11 09 2c 40 00 7e 1c 00 00 0a 72 } //2
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_2 = {54 00 72 00 6f 00 6a 00 61 00 6e 00 5f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 } //1 Trojan_Locker
		$a_01_3 = {62 00 6c 00 75 00 65 00 5f 00 73 00 6b 00 75 00 6c 00 6c 00 } //1 blue_skull
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}