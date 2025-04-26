
rule Ransom_Win32_Crysis_MK_MTB{
	meta:
		description = "Ransom:Win32/Crysis.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_81_1 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //1 bcdedit.exe /set {default} recoveryenabled No
		$a_81_2 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //1 bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
		$a_81_3 = {46 49 4c 45 53 20 45 4e 43 52 59 50 54 45 44 2e 74 78 74 } //1 FILES ENCRYPTED.txt
		$a_81_4 = {61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 20 75 73 } //1 all your data has been locked us
		$a_81_5 = {54 6f 74 61 6c 20 45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 20 3a } //1 Total Encrypted Files :
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}