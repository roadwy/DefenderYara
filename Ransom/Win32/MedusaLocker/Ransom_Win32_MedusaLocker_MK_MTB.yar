
rule Ransom_Win32_MedusaLocker_MK_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //vssadmin.exe Delete Shadows /All /Quiet  1
		$a_80_1 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //bcdedit.exe /set {default} recoveryenabled No  1
		$a_80_2 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures  1
		$a_80_3 = {77 62 61 64 6d 69 6e 20 44 45 4c 45 54 45 20 53 59 53 54 45 4d 53 54 41 54 45 42 41 43 4b 55 50 } //wbadmin DELETE SYSTEMSTATEBACKUP  1
		$a_80_4 = {77 6d 69 63 2e 65 78 65 20 53 48 41 44 4f 57 43 4f 50 59 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //wmic.exe SHADOWCOPY /nointeractive  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}