
rule Trojan_Win32_Zusy_NUA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 59 66 45 65 73 77 78 6f 79 6d 78 78 } //2 SYfEeswxoymxx
		$a_81_1 = {58 52 73 59 76 77 4d 66 51 51 71 62 49 6c 5a 6a 44 55 68 56 6e 72 54 58 4f 41 56 4d 6c 57 77 67 65 45 59 } //1 XRsYvwMfQQqbIlZjDUhVnrTXOAVMlWwgeEY
		$a_81_2 = {77 72 5a 59 53 6c 6c 43 55 79 56 54 52 6f 41 69 69 7a 74 6d 41 78 } //1 wrZYSllCUyVTRoAiiztmAx
		$a_81_3 = {46 70 63 46 4a 64 71 6e 48 6b 41 72 73 49 79 6c 6d 4f 6f 74 41 4f 6f 70 55 6f 43 70 46 6f 65 69 74 48 70 73 54 58 73 59 77 } //1 FpcFJdqnHkArsIylmOotAOopUoCpFoeitHpsTXsYw
		$a_81_4 = {73 73 69 42 41 53 51 4c 71 6c 68 59 64 47 78 75 53 56 46 43 49 4c 42 51 72 6e 6a 62 69 59 57 6a 70 79 4e 6a 47 76 4b 62 76 68 4c 4c 70 4f 63 68 4a 47 4f 69 47 77 6a 70 78 58 41 72 6d 50 73 4e 4b 71 6e 4e 59 41 6d 44 68 7a 4a 71 72 71 5a } //1 ssiBASQLqlhYdGxuSVFCILBQrnjbiYWjpyNjGvKbvhLLpOchJGOiGwjpxXArmPsNKqnNYAmDhzJqrqZ
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}