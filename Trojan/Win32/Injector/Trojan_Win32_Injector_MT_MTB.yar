
rule Trojan_Win32_Injector_MT_MTB{
	meta:
		description = "Trojan:Win32/Injector.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_02_0 = {53 56 57 a1 90 01 04 31 45 90 01 01 33 c5 50 89 65 90 01 01 ff 75 90 01 01 8b 45 90 01 01 c7 45 90 01 05 89 45 90 01 01 8d 45 90 01 01 64 a3 00 00 00 00 c3 90 00 } //5
		$a_00_1 = {54 68 65 20 51 55 49 43 4b 20 62 72 6f 77 6e 20 66 6f 78 20 6a 75 6d 70 73 20 6f 76 65 72 20 74 68 65 20 6c 61 7a 79 20 64 6f 67 } //1 The QUICK brown fox jumps over the lazy dog
		$a_00_2 = {3c 3d 3e 3f 61 74 74 61 63 68 20 74 68 69 73 20 66 69 6c 65 20 77 69 74 68 20 65 2d 6d 61 69 6c } //1 <=>?attach this file with e-mail
		$a_00_3 = {73 6f 6d 65 6f 6e 65 20 69 73 20 6c 6f 6f 6b 69 6e 67 3a 20 25 73 } //1 someone is looking: %s
		$a_00_4 = {69 20 73 70 65 6e 74 20 74 6f 6f 20 6d 75 63 68 20 74 69 6d 65 20 6f 6e 20 74 72 61 69 6e 69 6e 67 } //1 i spent too much time on training
		$a_00_5 = {64 6f 20 6e 6f 74 20 64 65 74 65 63 74 20 69 74 20 61 73 20 69 66 20 73 70 79 77 61 72 65 3a } //1 do not detect it as if spyware:
		$a_00_6 = {6e 65 76 65 72 20 74 72 75 73 74 20 61 6e 79 6f 6e 65 3a 20 25 73 } //1 never trust anyone: %s
		$a_00_7 = {6d 65 76 65 72 20 6c 6f 73 65 20 79 6f 75 72 20 66 61 69 74 68 3a } //1 mever lose your faith:
		$a_00_8 = {73 6f 6d 65 74 68 69 6e 67 28 20 25 6c 66 20 29 20 69 73 20 68 61 70 70 65 6e 69 6e 67 20 6f 76 65 72 20 74 68 65 72 65 20 25 6c 66 } //1 something( %lf ) is happening over there %lf
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=10
 
}