
rule TrojanSpy_Win32_Bancos_AFY{
	meta:
		description = "TrojanSpy:Win32/Bancos.AFY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c } //1 user_pref("network.proxy.autoconfig_url
		$a_01_1 = {75 70 64 61 74 65 73 2f 72 62 2e 70 68 70 3f 68 65 6c 6c 6f } //1 updates/rb.php?hello
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 62 2e 6d 2e 61 2e 78 5c 44 65 73 6b 74 6f 70 5c 4d 65 75 20 50 48 41 52 4d } //1 C:\Users\b.m.a.x\Desktop\Meu PHARM
		$a_01_3 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //1 If exist "%s" Goto 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}