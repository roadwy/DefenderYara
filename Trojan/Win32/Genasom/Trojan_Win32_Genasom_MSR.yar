
rule Trojan_Win32_Genasom_MSR{
	meta:
		description = "Trojan:Win32/Genasom!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin.exe delete shadows /all /quiet
		$a_01_1 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //2 bcdedit.exe /set {default} recoveryenabled no
		$a_01_2 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //2 bcdedit.exe /set {current} bootstatuspolicy ignoreallfailures
		$a_00_3 = {4c 00 4f 00 4f 00 4b 00 2e 00 74 00 78 00 74 00 } //1 LOOK.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1) >=5
 
}