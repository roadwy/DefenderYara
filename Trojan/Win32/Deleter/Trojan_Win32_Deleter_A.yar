
rule Trojan_Win32_Deleter_A{
	meta:
		description = "Trojan:Win32/Deleter.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 6d 73 67 62 6f 78 28 22 49 20 6c 6f 76 65 20 79 6f 75 20 62 69 74 63 68 21 22 2c } //1 =msgbox("I love you bitch!",
		$a_03_1 = {65 63 68 6f 20 59 20 7c 20 46 4f 52 20 2f 46 20 22 74 6f 6b 65 6e 73 3d 31 2c 2a 20 64 65 6c 69 6d 73 3d 3a 20 22 20 25 25 6a 20 69 6e 20 28 46 49 6c 65 4c 69 73 74 5f [0-04] 2e 74 78 74 29 20 64 6f 20 64 65 6c 20 22 25 25 6a 3a 25 25 6b 22 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}