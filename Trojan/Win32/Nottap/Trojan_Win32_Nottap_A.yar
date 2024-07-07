
rule Trojan_Win32_Nottap_A{
	meta:
		description = "Trojan:Win32/Nottap.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {5c 70 69 70 65 5c 6c 73 61 72 70 63 } //\pipe\lsarpc  1
		$a_80_1 = {63 36 38 31 64 34 38 38 2d 64 38 35 30 2d 31 31 64 30 2d 38 63 35 32 2d 30 30 63 30 34 66 64 39 30 66 37 65 } //c681d488-d850-11d0-8c52-00c04fd90f7e  1
		$a_80_2 = {2f 63 65 72 74 73 72 76 2f 63 65 72 74 66 6e 73 68 2e 61 73 70 } ///certsrv/certfnsh.asp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}