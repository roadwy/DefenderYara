
rule Trojan_AndroidOS_DroidAp_A_MTB{
	meta:
		description = "Trojan:AndroidOS/DroidAp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 44 72 6f 69 64 50 68 6f 6e 65 53 74 61 74 65 4c 69 73 74 65 6e 65 72 } //1 _DroidPhoneStateListener
		$a_01_1 = {63 6f 6d 2f 68 62 77 2f 64 72 6f 69 64 61 70 70 } //1 com/hbw/droidapp
		$a_01_2 = {43 41 4c 4c 42 41 53 4b 41 55 54 4f 4b 49 4c 4c } //1 CALLBASKAUTOKILL
		$a_01_3 = {53 6d 73 53 65 6e 64 65 72 } //1 SmsSender
		$a_01_4 = {5f 43 61 6c 6c 4c 69 73 74 65 6e 65 72 } //1 _CallListener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}