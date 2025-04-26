
rule Trojan_Win32_Amadey_GM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c1 c7 05 [0-20] 01 05 [0-10] 8b ff 8b 15 [0-10] a1 [0-10] 89 02 } //1
		$a_02_1 = {03 f0 8b 55 ?? 03 32 8b 45 ?? 89 30 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}