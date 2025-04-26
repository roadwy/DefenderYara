
rule TrojanProxy_BAT_Banker_B{
	meta:
		description = "TrojanProxy:BAT/Banker.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 68 00 65 00 63 00 6b 00 69 00 6e 00 66 00 65 00 63 00 74 00 2e 00 70 00 68 00 70 00 } //1 /checkinfect.php
		$a_01_1 = {73 00 68 00 45 00 78 00 70 00 4d 00 61 00 74 00 63 00 68 00 28 00 68 00 6f 00 73 00 74 00 2c 00 20 00 73 00 61 00 6e 00 74 00 61 00 31 00 } //1 shExpMatch(host, santa1
		$a_01_2 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 46 00 69 00 6e 00 64 00 50 00 72 00 6f 00 78 00 79 00 46 00 6f 00 72 00 55 00 52 00 4c 00 28 00 75 00 72 00 6c 00 2c 00 20 00 68 00 6f 00 73 00 74 00 29 00 } //1 function FindProxyForURL(url, host)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}