
rule Trojan_BAT_AveMariaRAT_P_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 dd a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 81 00 00 00 24 00 00 00 ad 00 00 00 7f 01 } //2
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}