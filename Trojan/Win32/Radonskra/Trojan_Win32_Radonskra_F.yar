
rule Trojan_Win32_Radonskra_F{
	meta:
		description = "Trojan:Win32/Radonskra.F,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66 } //2 /create /tn SystemScript /tr "DWVALUE" /sc ONLOGON /f
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 63 72 69 70 74 53 79 73 00 } //1
		$a_01_2 = {2f 64 65 6c 65 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 66 } //1 /delete /tn SystemScript /f
		$a_01_3 = {77 69 6e 64 6f 77 73 2e 7a 70 78 } //1 windows.zpx
		$a_01_4 = {64 6f 77 73 2e 7a 70 7a } //1 dows.zpz
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}