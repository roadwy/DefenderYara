
rule DDoS_Win32_Nitol_P_bit{
	meta:
		description = "DDoS:Win32/Nitol.P!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 64 64 6f 73 2e 74 66 00 } //10
		$a_01_1 = {00 68 72 61 25 75 2e 64 6c 6c 00 } //1
		$a_01_2 = {5c 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 \%c%c%c%c%c.exe
		$a_01_3 = {00 25 64 2e 25 64 2e 25 64 2e 25 64 00 } //1
		$a_01_4 = {57 69 6e 64 6f 77 73 20 48 65 6c 70 20 53 79 73 74 65 6d 20 4d 79 73 73 } //1 Windows Help System Myss
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}