
rule Trojan_Win32_VB_AGE{
	meta:
		description = "Trojan:Win32/VB.AGE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9 89 45 ?? 89 4d ?? 6a 00 6a 00 6a 00 ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ff ff } //1
		$a_02_1 = {8d 45 08 ff 75 ?? 89 45 ?? c7 45 ?? 03 40 00 00 8d 5d ?? e8 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}