
rule Trojan_Win32_Agent_M_MTB{
	meta:
		description = "Trojan:Win32/Agent.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {51 6b 6b 62 61 6c } //1 Qkkbal
		$a_01_1 = {25 4d 67 72 2e 52 68 59 34 52 66 45 35 51 64 3a 66 } //1 %Mgr.RhY4RfE5Qd:f
		$a_01_2 = {65 78 74 64 2e 65 78 65 } //1 extd.exe
		$a_01_3 = {3a 3a 54 68 69 73 20 66 69 6c 65 20 77 69 6c 6c 20 74 65 61 63 68 20 68 6f 77 20 74 6f 20 6d 61 6b 65 20 61 20 76 69 72 75 73 3f } //1 ::This file will teach how to make a virus?
		$a_01_4 = {73 00 2e 00 62 00 61 00 74 00 } //1 s.bat
		$a_01_5 = {6f 00 73 00 2e 00 62 00 61 00 74 00 } //1 os.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}