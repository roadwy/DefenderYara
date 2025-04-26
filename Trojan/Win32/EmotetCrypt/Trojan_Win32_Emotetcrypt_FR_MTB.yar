
rule Trojan_Win32_Emotetcrypt_FR_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {65 6e 77 72 34 6e 72 76 63 32 2e 64 6c 6c } //1 enwr4nrvc2.dll
		$a_81_2 = {64 67 67 70 30 37 68 74 74 67 32 7a 6d 7a 68 6d 32 61 78 38 69 65 6b 6a 65 34 6b 63 6d 79 34 } //1 dggp07httg2zmzhm2ax8iekje4kcmy4
		$a_81_3 = {73 35 77 68 70 72 37 6a 30 37 32 76 79 6f 6a 37 62 67 6f } //1 s5whpr7j072vyoj7bgo
		$a_81_4 = {74 36 35 69 6b 6e 36 73 39 62 36 76 73 7a 6a 69 72 72 } //1 t65ikn6s9b6vszjirr
		$a_81_5 = {74 63 71 37 38 34 66 39 76 61 38 34 38 75 76 79 70 39 67 } //1 tcq784f9va848uvyp9g
		$a_81_6 = {66 63 65 31 6a 6e 62 74 30 6d 2e 64 6c 6c } //1 fce1jnbt0m.dll
		$a_81_7 = {68 31 67 79 71 6d 64 78 6a 30 76 61 79 63 63 66 38 78 66 6d 71 62 76 77 } //1 h1gyqmdxj0vayccf8xfmqbvw
		$a_81_8 = {6a 62 36 61 73 6f 68 71 78 6e 68 75 38 6b 74 72 61 34 6d 78 66 } //1 jb6asohqxnhu8ktra4mxf
		$a_81_9 = {72 70 69 68 6c 69 39 6d 6f 62 67 30 77 35 33 73 75 72 6b 67 34 } //1 rpihli9mobg0w53surkg4
		$a_81_10 = {72 72 64 76 62 7a 6c 62 73 6e 75 71 61 61 73 75 79 72 64 75 63 61 74 } //1 rrdvbzlbsnuqaasuyrducat
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=15
 
}