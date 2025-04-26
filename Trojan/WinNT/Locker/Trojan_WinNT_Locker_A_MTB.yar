
rule Trojan_WinNT_Locker_A_MTB{
	meta:
		description = "Trojan:WinNT/Locker.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 61 64 6d 65 6f 6e 6e 6f 74 65 70 61 64 2e 6a 61 76 61 65 6e 63 72 79 70 74 } //1 readmeonnotepad.javaencrypt
		$a_01_1 = {61 64 72 65 73 73 3a 42 41 57 34 56 4d 32 64 68 78 59 67 58 65 51 65 70 4f 48 4b 48 53 51 56 47 36 4e 67 61 45 62 39 34 } //1 adress:BAW4VM2dhxYgXeQepOHKHSQVG6NgaEb94
		$a_00_2 = {59 6f 75 20 6e 65 65 64 20 74 6f 20 73 65 6e 64 20 33 30 30 24 20 6f 66 20 62 69 74 63 6f 69 6e 73 } //1 You need to send 300$ of bitcoins
		$a_00_3 = {2e 6a 61 76 61 6c 6f 63 6b 65 72 } //1 .javalocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}