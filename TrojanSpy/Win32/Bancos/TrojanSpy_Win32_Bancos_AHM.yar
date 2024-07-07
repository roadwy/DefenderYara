
rule TrojanSpy_Win32_Bancos_AHM{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHM,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c 00 7c 00 20 00 73 00 68 00 45 00 78 00 70 00 4d 00 61 00 74 00 63 00 68 00 28 00 68 00 6f 00 73 00 74 00 2c 00 20 00 22 00 2a 00 5c 00 78 00 36 00 33 00 } //1 || shExpMatch(host, "*\x63
		$a_01_1 = {5c 00 63 00 68 00 65 00 63 00 6b 00 69 00 6e 00 66 00 65 00 63 00 74 00 2e 00 74 00 78 00 74 00 } //1 \checkinfect.txt
		$a_01_2 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 } //1 \GbPlugin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}