
rule Trojan_Win32_Dllhijack_GCM_MTB{
	meta:
		description = "Trojan:Win32/Dllhijack.GCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {59 58 4a 30 54 32 ?? 45 5a 57 31 68 ?? 6d 51 2b 64 48 ?? 31 5a } //10
		$a_01_1 = {4b 49 43 41 38 4c 31 4a 6c 5a 32 6c 7a 64 48 4a 68 64 47 6c 76 62 6b 6c 75 5a 6d 38 } //1 KICA8L1JlZ2lzdHJhdGlvbkluZm8
		$a_80_2 = {57 69 6e 64 6f 77 73 5c 49 4f 56 41 53 } //Windows\IOVAS  1
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 42 20 2f 63 20 22 25 73 22 } //1 cmd.exe /B /c "%s"
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}