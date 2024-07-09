
rule TrojanSpy_Win32_Wetoxy_B{
	meta:
		description = "TrojanSpy:Win32/Wetoxy.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 dc 5c c6 45 dd 64 c6 45 de 6f c6 45 df 63 c6 45 e0 75 c6 45 e1 6d c6 45 e2 65 c6 45 e3 6e c6 45 e4 74 c6 45 e5 73 c6 45 e6 2e c6 45 e7 6c c6 45 e8 6f c6 45 e9 67 c6 45 ea 00 } //1
		$a_03_1 = {fe ff ff 47 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 52 c6 85 ?? fe ff ff 61 c6 85 ?? fe ff ff 77 c6 85 ?? fe ff ff 49 c6 85 ?? fe ff ff 6e c6 85 ?? fe ff ff 70 c6 85 ?? fe ff ff 75 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 44 c6 85 ?? fe ff ff 61 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 61 } //1
		$a_01_2 = {5b 57 69 6e 64 6f 77 73 20 32 30 30 30 2f 58 50 3a 20 58 31 20 6d 6f 75 73 65 20 62 75 74 74 6f 6e 5d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}