
rule Trojan_Win32_NSISInject_VND_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.VND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {61 6e 74 69 76 61 63 63 69 6e 61 74 6f 72 20 62 65 63 61 75 73 65 2e 65 78 65 } //1 antivaccinator because.exe
		$a_81_1 = {66 75 6c 64 62 6c 6f 64 73 6f 70 64 72 74 74 65 72 65 6e 20 73 63 72 65 65 6e } //1 fuldblodsopdrtteren screen
		$a_81_2 = {67 72 61 74 75 6c 61 6e 74 20 73 76 72 64 66 73 74 65 20 67 74 74 65 74 } //1 gratulant svrdfste gttet
		$a_81_3 = {44 65 6c 69 63 61 74 65 6c 79 5c 6f 70 6c 67 65 74 73 2e 69 6e 69 } //1 Delicately\oplgets.ini
		$a_81_4 = {73 6b 75 6d 72 69 6e 67 73 74 69 6d 65 72 73 5c 55 6e 69 6e 73 74 61 6c 6c 5c 6e 65 67 72 65 73 73 5c 46 6f 72 6c 61 64 65 72 6e 65 73 } //1 skumringstimers\Uninstall\negress\Forladernes
		$a_81_5 = {68 75 72 72 69 65 72 73 5c 62 61 6c 6c 65 74 6b 6f 72 70 73 } //1 hurriers\balletkorps
		$a_81_6 = {70 72 6f 74 6f 6d 65 72 69 74 65 5c 62 6c 6f 6b 65 72 69 6e 67 65 72 6e 65 5c 6b 69 72 6b 65 6d 69 6e 69 73 74 65 72 69 65 74 73 } //1 protomerite\blokeringerne\kirkeministeriets
		$a_81_7 = {56 61 6e 73 6b 65 6c 69 67 67 6a 6f 72 64 65 73 38 38 2e 62 72 75 } //1 Vanskeliggjordes88.bru
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}