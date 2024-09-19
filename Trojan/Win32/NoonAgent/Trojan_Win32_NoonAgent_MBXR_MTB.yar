
rule Trojan_Win32_NoonAgent_MBXR_MTB{
	meta:
		description = "Trojan:Win32/NoonAgent.MBXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 40 00 04 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 14 4b 40 00 44 48 40 00 4c 29 40 00 78 } //3
		$a_01_1 = {46 49 4c 45 20 46 4f 4c 44 45 52 } //2 FILE FOLDER
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}