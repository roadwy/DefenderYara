
rule Trojan_Win32_RanumBot_MS_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d1 31 55 70 8b 4d 70 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 3d [0-04] 26 04 00 00 75 } //1
		$a_02_1 = {33 d1 31 55 70 8b 4d 70 8d 85 ?? ?? ?? ?? 90 18 29 08 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}