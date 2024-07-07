
rule Backdoor_Win32_Small_BP{
	meta:
		description = "Backdoor:Win32/Small.BP,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {09 50 69 64 3a 25 64 20 44 65 73 63 3a 20 25 73 0d 0a 00 } //1
		$a_01_1 = {78 53 6f 63 6b 65 74 00 76 53 6f 63 6b 65 74 00 } //1 卸捯敫t卶捯敫t
		$a_01_2 = {53 74 61 72 74 20 54 72 61 6e 73 6d 69 74 20 28 25 73 3a 25 64 20 3c 2d 3e 20 25 73 3a 25 64 29 20 2e 2e 2e 2e 2e 2e } //1 Start Transmit (%s:%d <-> %s:%d) ......
		$a_01_3 = {5b 2d 5d 20 41 63 63 65 70 74 31 20 65 72 72 6f 72 2e 0d 0a 00 } //1
		$a_01_4 = {f7 d1 2b f9 8b d1 87 f7 c1 e9 02 8b c7 f3 a5 8b ca 83 e1 03 f3 a4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}