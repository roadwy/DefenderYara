
rule PWS_BAT_Stealer_PA10_MTB{
	meta:
		description = "PWS:BAT/Stealer.PA10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {67 61 62 6b 61 75 72 69 63 40 67 6d 61 69 6c 2e 63 6f 6d } //gabkauric@gmail.com  2
		$a_80_1 = {73 6d 74 70 2e 67 6d 61 69 6c 2e 63 6f 6d } //smtp.gmail.com  1
		$a_80_2 = {59 40 4a 33 6a 42 23 3f 4c 62 6e 7a 4e 59 66 71 } //Y@J3jB#?LbnzNYfq  1
		$a_80_3 = {52 6f 62 6c 6f 78 4c 6f 67 69 6e 5f 5f 54 6f 74 61 6c 79 5f 4c 65 67 69 74 5f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //RobloxLogin__Totaly_Legit_.Properties.Resources  1
		$a_80_4 = {4c 6f 67 69 6e } //Login  1
		$a_80_5 = {50 61 73 73 77 6f 72 64 3a } //Password:  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=7
 
}