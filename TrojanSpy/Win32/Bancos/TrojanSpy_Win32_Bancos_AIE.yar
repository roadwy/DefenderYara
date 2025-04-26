
rule TrojanSpy_Win32_Bancos_AIE{
	meta:
		description = "TrojanSpy:Win32/Bancos.AIE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 68 45 78 70 4d 61 74 63 68 28 68 6f 73 74 2c 20 22 2a 5c 78 36 32 5c 78 37 32 5c 78 36 31 5c 78 36 34 5c 78 36 35 5c 78 37 33 5c 78 36 33 5c 78 36 66 5c 78 32 65 5c 78 36 33 5c 78 36 66 5c 78 36 64 5c 78 32 65 5c 78 36 32 5c 78 37 32 2a 22 29 } //1 shExpMatch(host, "*\x62\x72\x61\x64\x65\x73\x63\x6f\x2e\x63\x6f\x6d\x2e\x62\x72*")
		$a_01_1 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 22 2c 20 30 29 } //1 user_pref("network.proxy.type", 0)
		$a_01_2 = {5c 44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c } //1 \Dados de aplicativos\Mozilla\Firefox\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}