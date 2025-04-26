
rule Trojan_Win32_Redline_MBFA_MTB{
	meta:
		description = "Trojan:Win32/Redline.MBFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 81 f2 ?? ?? ?? ?? 88 14 08 8d 0d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 0c 24 } //1
		$a_01_1 = {6e 67 00 00 64 6a 68 62 63 79 68 75 79 73 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}