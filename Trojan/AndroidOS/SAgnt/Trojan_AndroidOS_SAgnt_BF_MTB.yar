
rule Trojan_AndroidOS_SAgnt_BF_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 4d 53 43 6f 75 6e 74 } //1 getSMSCount
		$a_01_1 = {67 65 74 50 68 6f 6e 65 } //1 getPhone
		$a_01_2 = {4d 65 73 73 61 67 65 53 65 6e 64 65 72 } //1 MessageSender
		$a_01_3 = {63 6f 6d 2f 73 6f 66 74 2f 61 6e 64 72 6f 69 64 2f 61 70 70 69 6e 73 74 61 6c 6c 65 72 } //1 com/soft/android/appinstaller
		$a_01_4 = {72 75 6c 65 73 5f 61 63 74 69 76 69 74 79 2e 74 78 74 } //1 rules_activity.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}