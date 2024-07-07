
rule Trojan_Win32_Emotetcrypt_JI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {58 68 59 76 39 6f 55 37 6e 51 33 28 71 45 71 6d 3e 2a 53 55 42 5e 76 43 6b 66 5e 78 38 63 5e 62 4e 76 79 39 73 4a 59 40 4c 72 6f 76 43 31 2b 4f 50 54 50 70 6c 36 52 2b 3c } //1 XhYv9oU7nQ3(qEqm>*SUB^vCkf^x8c^bNvy9sJY@LrovC1+OPTPpl6R+<
		$a_01_2 = {62 57 55 36 59 46 43 43 63 38 28 37 66 79 76 7a 33 69 61 3c 66 6d 26 49 37 35 32 6c 57 55 2b 4c 55 4f 5f 51 75 24 67 4e 79 61 50 50 49 65 52 37 4f 42 7a 47 35 62 43 4e 67 48 61 48 68 59 67 65 39 6b 64 24 6a 3c 55 } //1 bWU6YFCCc8(7fyvz3ia<fm&I752lWU+LUO_Qu$gNyaPPIeR7OBzG5bCNgHaHhYge9kd$j<U
		$a_01_3 = {32 5a 54 59 58 47 37 4b 35 23 52 59 2b 28 75 52 52 61 45 26 4c 58 49 76 46 21 2b 40 3e 6d 37 37 39 73 45 6a 42 55 29 64 28 4d 62 33 5f 21 5a } //1 2ZTYXG7K5#RY+(uRRaE&LXIvF!+@>m779sEjBU)d(Mb3_!Z
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}