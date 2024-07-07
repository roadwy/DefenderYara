
rule Trojan_Win32_Agent_EAF{
	meta:
		description = "Trojan:Win32/Agent.EAF,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 32 32 32 2e 37 33 2e 33 36 2e 36 38 3a 38 30 38 30 } //1 ://222.73.36.68:8080
		$a_01_1 = {2f 64 65 66 61 75 6c 74 32 2e 61 73 70 78 3f 6d 61 63 3d } //1 /default2.aspx?mac=
		$a_01_2 = {5c 77 69 6e 75 61 63 2e 6c 6e 6b } //1 \winuac.lnk
		$a_01_3 = {63 64 6d 69 2e 79 64 63 } //1 cdmi.ydc
		$a_01_4 = {75 63 64 2e 63 70 6d 22 20 73 65 74 63 6f 6e 66 69 67 } //1 ucd.cpm" setconfig
		$a_01_5 = {6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c } //1 lorer\Quick Launch\
		$a_01_6 = {5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //1 \Shell\Open\Command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}