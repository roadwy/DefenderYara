
rule Trojan_Win32_Vidar_AMMJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 } //1
		$a_03_1 = {83 45 ec 04 83 45 ?? 04 8b 45 ec 3b 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}