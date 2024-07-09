
rule Trojan_Win32_LemonDuck_A{
	meta:
		description = "Trojan:Win32/LemonDuck.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 63 68 74 61 73 6b 73 20 63 72 65 61 74 65 } //1 schtasks create
		$a_00_1 = {2f 72 75 20 73 79 73 74 65 6d } //1 /ru system
		$a_00_2 = {2f 73 63 20 4d 49 4e 55 54 45 20 2f 6d 6f } //1 /sc MINUTE /mo
		$a_00_3 = {2f 74 6e 20 62 6c 61 63 6b 62 61 6c 6c 20 2f 46 20 2f 74 72 20 22 62 6c 61 63 6b 62 61 6c 6c 22 } //4 /tn blackball /F /tr "blackball"
		$a_00_4 = {2f 74 6e 20 62 6c 75 65 74 65 61 20 2f 46 20 2f 74 72 20 22 62 6c 75 65 74 65 61 22 } //4 /tn bluetea /F /tr "bluetea"
		$a_02_5 = {2f 74 6e 20 52 74 73 61 [0-02] 20 2f 46 20 2f 74 72 20 22 70 6f 77 65 72 73 68 65 6c 6c } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4+(#a_02_5  & 1)*4) >=7
 
}