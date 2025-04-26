
rule Trojan_Win32_SilverSword_A_dha{
	meta:
		description = "Trojan:Win32/SilverSword.A!dha,SIGNATURE_TYPE_PEHSTR,ffffffe8 03 ffffffe8 03 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 73 79 73 63 6f 6e 66 2e 64 6c 6c } //1 C:\sysconf.dll
		$a_01_1 = {53 74 61 72 74 4b 65 79 6c 6f 67 } //1 StartKeylog
		$a_01_2 = {3c 44 65 6c 65 74 65 3e } //1 <Delete>
		$a_01_3 = {6d 73 6b 65 79 2e 64 6c 6c } //1 mskey.dll
		$a_01_4 = {5b 4b 65 79 73 5d } //1 [Keys]
		$a_01_5 = {63 6d 64 20 2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 20 3e 3e 20 22 25 73 22 } //1 cmd /c systeminfo >> "%s"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1000
 
}