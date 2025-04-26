
rule Trojan_BAT_CryptTrickldr_A_ibt{
	meta:
		description = "Trojan:BAT/CryptTrickldr.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_80_0 = {65 6e 61 62 6c 65 73 63 72 69 70 74 62 6c 6f 63 6b 69 6e 76 6f 63 61 74 69 6f 6e 6c 6f 67 67 69 6e 67 } //enablescriptblockinvocationlogging  1
		$a_80_1 = {77 69 6e 64 6f 77 73 5c 70 6f 77 65 72 73 68 65 6c 6c 5c 73 63 72 69 70 74 62 27 2b 27 6c 6f 63 6b 6c 6f 67 67 69 6e 67 27 } //windows\powershell\scriptb'+'locklogging'  1
		$a_80_2 = {77 65 62 63 6c 69 65 6e 74 3b 24 75 3d 27 6d 6f 7a 69 6c 6c 61 2f 35 2e 30 } //webclient;$u='mozilla/5.0  1
		$a_80_3 = {5b 74 65 78 74 2e 65 6e 63 6f 64 69 6e 67 5d 3a 3a 75 6e 69 63 6f 64 65 2e 67 65 74 73 74 72 69 6e 67 28 5b 63 6f 6e 76 65 72 74 5d 3a 3a 66 72 6f 6d 62 61 73 65 36 34 73 74 72 69 6e 67 28 27 61 61 62 30 61 68 71 61 63 61 61 36 61 63 38 61 6c 77 } //[text.encoding]::unicode.getstring([convert]::frombase64string('aab0ahqacaa6ac8alw  1
		$a_80_4 = {2f 61 64 6d 69 6e 2f 67 65 74 2e 70 68 70 } ///admin/get.php  1
		$a_80_5 = {2e 70 72 6f 78 79 3d 5b 73 79 73 74 65 6d 2e 6e 65 74 2e 77 65 62 72 65 71 75 65 73 74 5d } //.proxy=[system.net.webrequest]  1
		$a_80_6 = {2e 68 65 61 64 65 72 73 2e 61 64 64 28 27 75 73 65 72 2d 61 67 65 6e 74 27 2c } //.headers.add('user-agent',  1
		$a_80_7 = {24 5f 2d 62 78 6f 72 24 } //$_-bxor$  1
		$a_80_8 = {2e 64 6f 77 6e 6c 6f 61 64 64 61 74 61 28 } //.downloaddata(  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=6
 
}