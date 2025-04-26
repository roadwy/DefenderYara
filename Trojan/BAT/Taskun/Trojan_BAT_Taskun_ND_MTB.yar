
rule Trojan_BAT_Taskun_ND_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 91 09 61 07 08 17 58 07 8e 69 5d 91 } //5
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //2 InvokeMember
		$a_81_2 = {45 78 65 63 75 74 65 52 65 61 64 65 72 } //2 ExecuteReader
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=9
 
}