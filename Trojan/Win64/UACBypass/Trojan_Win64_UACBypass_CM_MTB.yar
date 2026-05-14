
rule Trojan_Win64_UACBypass_CM_MTB{
	meta:
		description = "Trojan:Win64/UACBypass.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 50 65 72 73 69 73 74 } //2 main.Persist
		$a_01_1 = {6d 61 69 6e 2e 42 79 70 61 73 73 } //2 main.Bypass
		$a_01_2 = {6d 61 69 6e 2e 43 72 65 61 74 65 52 65 67 4b 65 79 } //2 main.CreateRegKey
		$a_01_3 = {6d 61 69 6e 2e 52 75 6e 41 73 41 64 6d 69 6e } //2 main.RunAsAdmin
		$a_01_4 = {6d 61 69 6e 2e 49 73 45 6c 65 76 61 74 65 64 } //2 main.IsElevated
		$a_01_5 = {44 65 6c 65 67 61 74 65 45 78 65 63 75 74 65 } //2 DelegateExecute
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}