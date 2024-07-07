
rule Trojan_Win32_Agent_KU{
	meta:
		description = "Trojan:Win32/Agent.KU,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 53 76 63 68 6f 73 74 2e 74 78 74 } //10 \Svchost.txt
		$a_01_1 = {5c 53 76 63 68 6f 73 74 2e 72 65 67 } //10 \Svchost.reg
		$a_01_2 = {57 69 6e 64 73 } //1 Winds
		$a_01_3 = {5c 68 66 73 65 74 65 6d 70 2e 69 6e 69 } //1 \hfsetemp.ini
		$a_01_4 = {5c 25 64 5f 74 65 6d 2e 69 6e 66 6f } //1 \%d_tem.info
		$a_01_5 = {5c 65 73 65 6e 74 2e 64 6c 6c } //1 \esent.dll
		$a_01_6 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 %SystemRoot%\System32\svchost.exe -k netsvcs
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=23
 
}