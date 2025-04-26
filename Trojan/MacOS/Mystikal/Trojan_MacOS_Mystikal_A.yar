
rule Trojan_MacOS_Mystikal_A{
	meta:
		description = "Trojan:MacOS/Mystikal.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {59 58 42 6d 5a 57 78 73 4c 6d 6c 6b 49 43 73 67 53 6c 4e 50 54 69 35 7a 64 48 4a 70 62 6d 64 70 5a 6e 6b } //3 YXBmZWxsLmlkICsgSlNPTi5zdHJpbmdpZnk
		$a_00_1 = {61 57 59 6f 59 58 42 6d 5a 57 78 73 4c 6d 6c 6b 49 44 30 39 50 53 42 31 62 6d 52 6c 5a 6d 6c 75 5a 57 51 67 66 48 77 67 59 58 42 6d 5a 57 78 73 4c 6d 6c 6b 49 44 30 39 50 53 41 69 49 69 } //3 aWYoYXBmZWxsLmlkID09PSB1bmRlZmluZWQgfHwgYXBmZWxsLmlkID09PSAiIi
		$a_00_2 = {4a 43 68 37 49 6e 52 35 63 47 55 69 4f 69 41 6b 4b 43 49 30 4d 69 49 70 4c 43 41 69 59 6e 4e 70 65 69 49 36 49 44 51 77 4f 54 59 73 49 43 4a 77 5a 58 4a 74 49 6a 6f 67 5a 6d 46 73 63 32 56 39 4b 54 73 } //2 JCh7InR5cGUiOiAkKCI0MiIpLCAiYnNpeiI6IDQwOTYsICJwZXJtIjogZmFsc2V9KTs
		$a_00_3 = {70 6c 75 67 69 6e 2e 63 70 70 } //1 plugin.cpp
		$a_00_4 = {21 72 65 74 75 72 6e 56 61 6c } //1 !returnVal
		$a_00_5 = {5f 4f 42 4a 43 5f 43 4c 41 53 53 5f 24 5f 4f 53 41 53 63 72 69 70 74 } //1 _OBJC_CLASS_$_OSAScript
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}