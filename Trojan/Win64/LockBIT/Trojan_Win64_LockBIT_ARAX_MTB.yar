
rule Trojan_Win64_LockBIT_ARAX_MTB{
	meta:
		description = "Trojan:Win64/LockBIT.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 2f 73 20 2f 66 20 2f 71 20 43 3a 5c 2a 2e 62 61 6b } //2 del /s /f /q C:\*.bak
		$a_01_1 = {64 65 6c 20 2f 73 20 2f 66 20 2f 71 20 43 3a 5c 2a 2e 76 68 64 } //2 del /s /f /q C:\*.vhd
		$a_01_2 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //2 bcdedit /set {default} recoveryenabled No
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}