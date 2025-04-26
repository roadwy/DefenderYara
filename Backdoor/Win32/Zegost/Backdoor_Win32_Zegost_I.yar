
rule Backdoor_Win32_Zegost_I{
	meta:
		description = "Backdoor:Win32/Zegost.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 20 25 64 00 } //1 汇扯污䝜と瑳┠d
		$a_03_1 = {c6 86 b5 00 00 00 00 a1 ?? ?? ?? ?? 85 c0 74 14 83 f8 04 74 0f 83 f8 05 74 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}