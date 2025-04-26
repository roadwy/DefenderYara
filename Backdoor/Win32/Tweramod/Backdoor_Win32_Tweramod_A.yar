
rule Backdoor_Win32_Tweramod_A{
	meta:
		description = "Backdoor:Win32/Tweramod.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 45 78 69 74 21 } //1 Shell Exit!
		$a_01_1 = {55 6e 61 62 6c 65 20 74 6f 20 54 72 61 76 65 72 73 65 20 46 6f 6c 64 65 72 21 } //1 Unable to Traverse Folder!
		$a_01_2 = {53 65 72 76 69 63 65 20 73 74 6f 70 65 64 } //1 Service stoped
		$a_01_3 = {48 65 6c 6c 6f 2c 48 65 6c 6c 21 } //1 Hello,Hell!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}