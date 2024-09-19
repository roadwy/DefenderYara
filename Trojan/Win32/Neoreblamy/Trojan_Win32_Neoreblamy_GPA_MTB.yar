
rule Trojan_Win32_Neoreblamy_GPA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 79 77 6a 52 55 52 76 54 48 78 46 6b 6b } //1 RywjRURvTHxFkk
		$a_01_1 = {45 6b 44 6d 52 54 48 56 4c 71 42 6f 4a 76 65 74 77 63 73 4c 6a 4d 77 } //3 EkDmRTHVLqBoJvetwcsLjMw
		$a_01_2 = {46 67 62 64 49 59 75 62 43 41 6e 61 45 6c 62 47 6a 6c 71 } //5 FgbdIYubCAnaElbGjlq
		$a_01_3 = {71 51 70 74 78 4d 6f 6d 6b 4e 79 6d 75 4f 71 58 4d 72 57 58 62 61 } //7 qQptxMomkNymuOqXMrWXba
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*5+(#a_01_3  & 1)*7) >=16
 
}