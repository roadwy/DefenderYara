
rule PWS_Win32_Bisty_A{
	meta:
		description = "PWS:Win32/Bisty.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {7b 65 33 64 66 36 62 34 31 39 64 31 66 7d 90 0a 43 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c } //5
		$a_01_1 = {3c 50 72 65 76 69 6f 75 73 20 54 72 61 63 6b 20 6b 65 79 3e } //1 <Previous Track key>
		$a_01_2 = {4f 75 74 6c 6f 6f 6b 32 30 30 33 5f 49 4d 41 50 00 00 00 00 4f 75 74 6c 6f 6f 6b 32 30 30 32 5f 49 4d 41 50 } //2
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=5
 
}