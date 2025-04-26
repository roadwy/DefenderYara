
rule Trojan_Win32_CobaltStrike_RE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 4c 46 14 89 46 0c 8b 07 a8 40 } //1
		$a_01_1 = {66 89 5c 46 1a 0f b7 5c 47 34 66 85 db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}