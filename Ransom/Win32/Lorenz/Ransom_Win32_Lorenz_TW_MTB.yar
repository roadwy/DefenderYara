
rule Ransom_Win32_Lorenz_TW_MTB{
	meta:
		description = "Ransom:Win32/Lorenz.TW!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 72 65 6e 7a 2e 73 7a 34 30 } //1 Lorenz.sz40
		$a_01_1 = {53 43 48 54 41 53 4b 53 20 2f 72 75 6e 20 2f 54 4e 20 73 7a 34 30 31 26 53 43 48 54 41 53 4b 53 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 73 7a 34 30 31 20 2f 46 } //1 SCHTASKS /run /TN sz401&SCHTASKS /Delete /TN sz401 /F
		$a_01_2 = {2f 50 41 53 53 57 4f 52 44 3a 27 63 72 6f 77 65 6e 27 } //1 /PASSWORD:'crowen'
		$a_01_3 = {31 35 37 2e 39 30 2e 31 34 37 2e 32 38 } //1 157.90.147.28
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}