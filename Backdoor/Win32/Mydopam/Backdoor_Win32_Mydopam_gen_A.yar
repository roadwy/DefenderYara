
rule Backdoor_Win32_Mydopam_gen_A{
	meta:
		description = "Backdoor:Win32/Mydopam.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 6f 74 6f 20 74 72 79 0d 0a 64 65 6c 20 43 3a 5c 54 45 4d 50 5c 6d 73 69 64 65 6c 2e 62 61 74 } //2
		$a_01_1 = {48 54 54 50 1a 0f 0f 57 57 57 0e 53 50 41 4d 43 41 54 43 48 45 52 4f 0e 42 49 5a 0f 44 4c 0f 42 4f 54 0e 44 4c 4c } //2 呈偔༚圏块匎䅐䍍呁䡃剅๏䥂ཚ䱄䈏呏䐎䱌
		$a_01_2 = {2a 48 54 54 50 1a 0f 0f 49 46 52 41 4d 45 42 49 5a 2e 43 4f 4d 2e 45 58 45 2e 50 48 50 2e 55 49 44 2e } //2 䠪呔ᩐ༏䙉䅒䕍䥂⹚佃⹍塅⹅䡐⹐䥕⹄
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //1 Software\Microsoft\Security Center
		$a_01_4 = {46 69 72 65 77 61 6c 6c 4f 76 65 72 72 69 64 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1
		$a_01_5 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 74 72 79 0d 0a 64 65 6c 20 25 73 0d 0a 69 66 20 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 74 72 79 0d 0a 64 65 6c 20 25 73 2e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}