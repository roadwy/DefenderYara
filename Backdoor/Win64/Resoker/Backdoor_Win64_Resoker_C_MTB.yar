
rule Backdoor_Win64_Resoker_C_MTB{
	meta:
		description = "Backdoor:Win64/Resoker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //5 https://api.telegram.org/bot
		$a_01_1 = {2f 73 63 72 65 65 6e 73 68 6f 74 } //5 /screenshot
		$a_01_2 = {2f 75 61 63 5f 6d 61 78 } //5 /uac_max
		$a_01_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //5 DisableTaskMgr
		$a_01_4 = {42 6f 74 20 74 68 72 65 61 64 20 73 74 61 72 74 65 64 } //5 Bot thread started
		$a_01_5 = {52 45 53 4f 4b 45 52 20 53 54 41 52 54 45 44 20 5b 48 49 44 44 45 4e 20 4d 4f 44 45 5d } //5 RESOKER STARTED [HIDDEN MODE]
		$a_01_6 = {53 63 72 65 65 6e 73 68 6f 74 20 63 72 65 61 74 65 64 3a } //5 Screenshot created:
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=35
 
}