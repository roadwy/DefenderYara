
rule Ransom_Win32_Amnesia_MK_MTB{
	meta:
		description = "Ransom:Win32/Amnesia.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 49 44 6b 2e 74 78 74 } //5 C:\ProgramData\IDk.txt
		$a_81_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 70 75 62 6b 2e 74 78 74 } //5 C:\ProgramData\pubk.txt
		$a_81_2 = {2e 53 6f 70 68 6f 73 } //10 .Sophos
		$a_81_3 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //2 bcdedit /set {default} bootstatuspolicy ignoreallfailures
		$a_81_4 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //2 bcdedit /set {default} recoveryenabled no
		$a_81_5 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //2 wbadmin delete catalog -quiet
		$a_81_6 = {59 6f 75 72 20 46 69 6c 65 73 20 48 61 73 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //10 Your Files Has Been Encrypted
		$a_00_7 = {76 00 6d 00 73 00 73 00 32 00 63 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //-100 vmss2core.exe
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*10+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*10+(#a_00_7  & 1)*-100) >=34
 
}