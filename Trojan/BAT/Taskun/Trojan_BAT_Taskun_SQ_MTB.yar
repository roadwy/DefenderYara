
rule Trojan_BAT_Taskun_SQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0f 00 28 ab 00 00 0a 16 61 d2 9c 25 17 0f 00 28 ac 00 00 0a 16 60 d2 9c 25 18 0f 00 28 ad 00 00 0a 20 ff 00 00 00 5f d2 9c } //2
		$a_81_1 = {4d 61 72 6b 73 68 65 65 74 5f 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Marksheet_Project.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}