
rule Trojan_Win32_Azorult_DS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 83 2d ?? ?? ?? ?? 01 0f } //1
		$a_02_1 = {6a 00 6a 00 e8 ?? ?? ?? ?? 4b 90 0a 10 00 bb ?? ?? ?? 00 [0-10] 75 } //1
		$a_02_2 = {5a 59 59 64 89 10 68 ?? ?? ?? ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}