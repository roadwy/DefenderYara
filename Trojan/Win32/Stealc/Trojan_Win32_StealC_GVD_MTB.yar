
rule Trojan_Win32_StealC_GVD_MTB{
	meta:
		description = "Trojan:Win32/StealC.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {01 f1 81 e9 ?? ?? ?? ?? 31 01 59 52 } //2
		$a_01_1 = {01 d1 01 19 59 5a 83 ec 04 89 14 24 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}