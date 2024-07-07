
rule Trojan_Win32_Dridex_PAB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 70 72 65 69 6e 73 74 61 6c 6c 65 64 2c 74 68 65 75 6e 6c 69 6b 65 6d 6f 6e 62 6f 6e 64 30 30 37 73 69 6d 70 6c 69 66 69 65 64 42 61 6b } //1 Ipreinstalled,theunlikemonbond007simplifiedBak
		$a_01_1 = {43 68 72 6f 6d 65 41 77 61 73 47 6f 6f 67 6c 65 75 6e 73 74 61 62 6c 65 62 79 6e 69 6e 65 74 68 65 47 6f 6f 67 6c 65 } //1 ChromeAwasGoogleunstablebyninetheGoogle
		$a_01_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 4c 00 59 00 65 00 65 00 6e 00 63 00 6f 00 75 00 72 00 61 00 67 00 65 00 56 00 63 00 61 00 6e 00 69 00 } //1 systemLYeencourageVcani
		$a_01_3 = {4c 00 6f 00 63 00 61 00 6c 00 4f 00 6d 00 6e 00 69 00 62 00 6f 00 78 00 74 00 68 00 65 00 5a 00 48 00 6f 00 6e 00 6c 00 79 00 } //1 LocalOmniboxtheZHonly
		$a_01_4 = {67 72 61 6e 74 6b 7a 69 6e 74 65 72 61 63 74 69 76 69 74 79 } //1 grantkzinteractivity
		$a_01_5 = {75 00 70 00 64 00 61 00 74 00 65 00 73 00 75 00 53 00 70 00 65 00 65 00 64 00 } //1 updatesuSpeed
		$a_01_6 = {49 63 6d 70 36 53 65 6e 64 45 63 68 6f 32 } //1 Icmp6SendEcho2
		$a_01_7 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 } //1 AntiVir
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}