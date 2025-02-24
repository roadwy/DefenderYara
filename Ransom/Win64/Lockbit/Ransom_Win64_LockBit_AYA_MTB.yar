
rule Ransom_Win64_LockBit_AYA_MTB{
	meta:
		description = "Ransom:Win64/LockBit.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 20 53 65 6e 64 20 35 20 42 54 43 20 74 6f 20 75 6e 6c 6f 63 6b 2e } //3 YOUR FILES HAVE BEEN ENCRYPTED! Send 5 BTC to unlock.
		$a_01_1 = {52 41 4e 53 4f 4d 5f 4e 4f 54 45 2e 74 78 74 } //1 RANSOM_NOTE.txt
		$a_01_2 = {6e 65 74 20 75 73 65 72 20 54 72 6f 6a 61 6e 55 73 65 72 } //1 net user TrojanUser
		$a_01_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_5 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_01_6 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_7 = {62 63 64 65 64 69 74 20 2f 64 65 6c 65 74 65 20 7b 62 6f 6f 74 6d 67 72 7d 20 2f 66 } //1 bcdedit /delete {bootmgr} /f
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}