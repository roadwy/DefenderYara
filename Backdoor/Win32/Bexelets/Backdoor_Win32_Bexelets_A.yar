
rule Backdoor_Win32_Bexelets_A{
	meta:
		description = "Backdoor:Win32/Bexelets.A,SIGNATURE_TYPE_PEHSTR,05 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {07 45 78 65 63 75 74 65 08 54 42 6f 74 4b 69 6c 6c } //2
		$a_01_1 = {07 65 78 65 63 75 74 65 07 54 4f 6d 65 67 6c 65 } //2 攇數畣整吇浏来敬
		$a_01_2 = {4e 6f 20 70 61 73 73 77 6f 72 64 73 20 6c 6f 67 67 65 64 7c } //1 No passwords logged|
		$a_01_3 = {54 54 63 70 41 74 6b } //1 TTcpAtk
		$a_01_4 = {54 55 64 70 41 74 6b } //1 TUdpAtk
		$a_01_5 = {41 64 64 44 4e 53 53 70 6f 6f 66 } //1 AddDNSSpoof
		$a_01_6 = {6c 6c 64 2e 6c 6c 44 65 69 62 53 } //1 lld.llDeibS
		$a_01_7 = {42 4b 2e 45 58 43 2e } //1 BK.EXC.
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}