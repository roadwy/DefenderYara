
rule Trojan_Win32_Maganpy_A_bit{
	meta:
		description = "Trojan:Win32/Maganpy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 64 6c 6c } //1 svchost.dll
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 25 73 20 2f 54 } //1 taskkill /F /IM %s /T
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}