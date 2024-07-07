
rule Trojan_Win32_Winnti_Q_dha{
	meta:
		description = "Trojan:Win32/Winnti.Q!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 20 20 3c 42 61 63 6b 64 6f 6f 72 3e 20 5b 44 72 69 76 65 72 4c 65 74 74 65 72 5d 20 20 20 3a 20 20 20 20 49 6e 73 74 61 6c 6c 20 48 44 44 } //1 inst  <Backdoor> [DriverLetter]   :    Install HDD
		$a_01_1 = {48 44 44 20 52 6f 6f 74 6b 69 74 } //1 HDD Rootkit
		$a_01_2 = {5c 69 33 38 36 5c 48 64 64 49 6e 73 74 61 6c 6c 2e 70 64 62 } //1 \i386\HddInstall.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}