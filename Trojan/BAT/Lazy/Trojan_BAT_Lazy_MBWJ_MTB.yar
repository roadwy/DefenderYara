
rule Trojan_BAT_Lazy_MBWJ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.MBWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 52 6c 57 54 6d 5a 77 6d 70 44 6b 34 4b 64 37 70 4a 51 5a 67 6a 4e 70 6c 69 39 5a 50 46 36 5a 4c 49 51 67 63 4c 76 71 64 4e 31 76 6c 59 38 4e 70 4a 4d 31 68 53 59 39 6c 33 6f 32 48 57 66 49 53 56 47 38 69 4e 54 70 4c 42 65 69 6e 41 } //2 lRlWTmZwmpDk4Kd7pJQZgjNpli9ZPF6ZLIQgcLvqdN1vlY8NpJM1hSY9l3o2HWfISVG8iNTpLBeinA
		$a_01_1 = {6d 38 65 47 36 77 6c 38 35 36 46 38 6a 50 4d 68 4d 41 52 51 39 65 74 51 } //1 m8eG6wl856F8jPMhMARQ9etQ
		$a_01_2 = {45 6d 2f 66 45 34 37 43 6c 43 75 32 36 33 6c 77 57 49 50 65 33 47 41 53 6c 65 4c 42 63 2f 45 } //1 Em/fE47ClCu263lwWIPe3GASleLBc/E
		$a_01_3 = {41 6e 74 69 2d 56 54 2e 65 78 65 } //1 Anti-VT.exe
		$a_01_4 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_01_5 = {61 65 39 63 65 64 36 32 37 31 63 31 } //1 ae9ced6271c1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}