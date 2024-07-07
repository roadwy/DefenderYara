
rule TrojanSpy_AndroidOS_Mploit_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mploit.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //1 content://call_log/calls
		$a_00_1 = {63 6f 6d 2e 65 74 65 63 68 64 2e 6c 33 6d 6f 6e } //1 com.etechd.l3mon
		$a_00_2 = {26 6d 61 6e 66 3d } //1 &manf=
		$a_00_3 = {63 6f 6e 74 61 63 74 73 4c 69 73 74 } //1 contactsList
		$a_00_4 = {63 6f 6d 2e 73 75 70 70 6f 72 74 2e 61 70 70 7a } //1 com.support.appz
		$a_00_5 = {4d 61 6c 66 6f 72 6d 65 64 20 63 6c 6f 73 65 20 70 61 79 6c 6f 61 64 20 } //1 Malformed close payload 
		$a_00_6 = {70 61 63 6b 61 67 65 3a 63 6f 6d 2e 72 65 6d 6f 74 65 2e 61 70 70 } //1 package:com.remote.app
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}