
rule VirTool_Win32_Ekocit_A_MTB{
	meta:
		description = "VirTool:Win32/Ekocit.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 6d 65 6e 7a 68 69 6e 73 6b 79 2f 67 6f 2d 6d 65 6d 65 78 65 63 } //1 amenzhinsky/go-memexec
		$a_01_1 = {67 6f 2d 6d 65 6d 65 78 65 63 2e 28 2a 45 78 65 63 29 2e 43 6f 6d 6d 61 6e 64 } //1 go-memexec.(*Exec).Command
		$a_01_2 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 } //1 main.decrypt
		$a_00_3 = {50 a7 f4 51 53 65 41 7e c3 a4 17 1a 96 5e 27 3a cb 6b ab 3b f1 45 9d 1f ab 58 fa ac 93 03 e3 4b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}