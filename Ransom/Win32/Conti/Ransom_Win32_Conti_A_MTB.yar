
rule Ransom_Win32_Conti_A_MTB{
	meta:
		description = "Ransom:Win32/Conti.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 43 4f 4e 54 49 5f 52 45 41 44 4d 45 2e 74 78 74 } //1 \CONTI_README.txt
		$a_81_1 = {54 68 65 20 73 79 73 74 65 6d 20 69 73 20 4c 4f 43 4b 45 44 2e 20 44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 75 6e 6c 6f 63 6b 20 77 69 74 68 20 6f 74 68 65 72 20 73 6f 66 74 77 61 72 65 2e 20 46 6f 72 20 4b 45 59 20 77 72 69 74 65 20 6f 6e 20 65 6d 61 69 6c 73 3a } //1 The system is LOCKED. Do not try to unlock with other software. For KEY write on emails:
		$a_81_2 = {5c 61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 \aaa_TouchMeNot_.txt
		$a_03_3 = {8a 84 1d f0 [0-04] 34 ?? 88 84 1d [0-04] 43 83 fb ?? 7c } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}