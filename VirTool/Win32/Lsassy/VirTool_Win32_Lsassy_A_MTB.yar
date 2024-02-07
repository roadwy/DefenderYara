
rule VirTool_Win32_Lsassy_A_MTB{
	meta:
		description = "VirTool:Win32/Lsassy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 73 61 73 73 79 2e 65 78 65 63 2e 77 6d 69 } //01 00  lsassy.exec.wmi
		$a_01_1 = {6c 73 61 73 73 79 2e 64 75 6d 70 65 72 } //01 00  lsassy.dumper
		$a_01_2 = {6c 73 61 73 73 79 2e 63 72 65 64 65 6e 74 69 61 6c } //01 00  lsassy.credential
		$a_01_3 = {64 75 6d 70 6d 65 74 68 6f 64 2e 64 75 6d 70 65 72 74 } //01 00  dumpmethod.dumpert
		$a_01_4 = {64 75 6d 70 6d 65 74 68 6f 64 2e 64 6c 6c 69 6e 6a 65 63 74 } //01 00  dumpmethod.dllinject
		$a_01_5 = {6d 69 6e 69 64 75 6d 70 2e 73 74 72 65 61 6d 73 } //01 00  minidump.streams
		$a_01_6 = {6d 69 6e 69 6b 65 72 62 65 72 6f 73 2e 63 6f 6d 6d 6f 6e } //01 00  minikerberos.common
		$a_01_7 = {70 79 70 79 6b 61 74 7a } //00 00  pypykatz
	condition:
		any of ($a_*)
 
}