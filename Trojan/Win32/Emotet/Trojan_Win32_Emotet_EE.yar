
rule Trojan_Win32_Emotet_EE{
	meta:
		description = "Trojan:Win32/Emotet.EE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 65 78 63 6c 75 73 69 6f 6e 75 73 65 64 72 65 66 6c 65 63 74 73 49 6e 74 65 72 6e 65 74 61 6c 6c 6f 77 73 55 70 64 61 74 65 6f 66 66 65 72 } //1 webexclusionusedreflectsInternetallowsUpdateoffer
		$a_01_1 = {77 44 65 76 68 74 72 61 6e 73 69 74 69 6f 6e 73 2c 36 53 6a 61 69 6c 2e 38 32 30 30 38 2c 66 72 65 71 75 65 6e 74 } //1 wDevhtransitions,6Sjail.82008,frequent
		$a_01_2 = {61 63 63 6f 72 64 69 6e 67 41 43 68 72 6f 6d 65 77 53 65 63 75 72 69 74 79 59 61 6e 64 70 72 65 76 69 6f 75 73 6c 79 38 } //1 accordingAChromewSecurityYandpreviously8
		$a_01_3 = {75 00 73 00 65 00 72 00 73 00 6c 00 79 00 65 00 74 00 2e 00 31 00 33 00 33 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 65 00 72 00 43 00 61 00 6e 00 61 00 72 00 79 00 74 00 6f 00 6d 00 63 00 61 00 74 00 } //1 userslyet.133DeveloperCanarytomcat
		$a_01_4 = {6e 00 61 00 74 00 68 00 61 00 6e 00 53 00 6e 00 78 00 6c 00 6f 00 63 00 61 00 6c 00 6e 00 6f 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 63 00 79 00 63 00 6c 00 65 00 73 00 2e 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //1 nathanSnxlocalnocontrolcycles.security
		$a_01_5 = {73 00 65 00 6f 00 66 00 6e 00 75 00 6d 00 62 00 65 00 72 00 33 00 43 00 68 00 72 00 6f 00 6d 00 65 00 58 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 4c 00 } //1 seofnumber3ChromeXversionL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}