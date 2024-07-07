
rule Trojan_Win32_Herdceded_A{
	meta:
		description = "Trojan:Win32/Herdceded.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 65 66 69 6e 65 28 55 72 6c 53 65 72 76 65 72 20 2c 20 27 68 74 74 70 3a 2f 2f 67 65 74 76 6f 6c 6b 65 72 64 6e 73 2e 63 6f 2e 63 63 2f 70 72 69 76 38 27 29 } //1 define(UrlServer , 'http://getvolkerdns.co.cc/priv8')
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 73 43 6c 69 65 6e 74 2f 62 6f 74 73 2e 70 68 70 3f 6e 61 6d 65 3d } //1 FunctionsClient/bots.php?name=
		$a_01_2 = {43 68 65 63 6b 42 6f 74 28 29 } //1 CheckBot()
		$a_01_3 = {50 68 61 72 6d 69 6e 67 28 29 } //1 Pharming()
		$a_01_4 = {73 6c 65 65 70 28 53 65 63 6f 6e 73 29 } //1 sleep(Secons)
		$a_01_5 = {46 75 6e 63 74 69 6f 6e 73 43 6c 69 65 6e 74 2f 68 6f 73 74 2e 70 68 70 } //1 FunctionsClient/host.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}