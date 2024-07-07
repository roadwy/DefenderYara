
rule Trojan_Win32_Farfli_AP_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a 8b 45 08 83 c0 01 89 45 08 } //2
		$a_01_1 = {77 77 77 2e 78 79 39 39 39 2e 63 6f 6d } //1 www.xy999.com
		$a_01_2 = {66 75 63 6b 79 6f 75 } //1 fuckyou
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}