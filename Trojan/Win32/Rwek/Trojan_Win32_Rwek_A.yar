
rule Trojan_Win32_Rwek_A{
	meta:
		description = "Trojan:Win32/Rwek.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 6b 65 79 3a 7e 30 2c 31 25 66 25 6b 65 79 3a 7e 38 2c 31 25 6c 25 6b 65 79 3a 7e 38 2c 31 25 61 25 6b 65 79 3a 7e 33 2c 31 25 6f 73 2e 72 61 70 25 6b 65 79 3a 7e 38 2c 31 25 64 2d 63 6f 6e 66 25 6b 65 79 3a 7e 38 2c 31 25 72 6d 2e 63 25 6b 65 79 3a 7e 31 34 2c 31 25 6d } //1 %key:~0,1%f%key:~8,1%l%key:~8,1%a%key:~3,1%os.rap%key:~8,1%d-conf%key:~8,1%rm.c%key:~14,1%m
		$a_01_1 = {25 5c 74 68 75 6e 62 2e 64 62 22 20 36 36 36 22 } //1 %\thunb.db" 666"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}