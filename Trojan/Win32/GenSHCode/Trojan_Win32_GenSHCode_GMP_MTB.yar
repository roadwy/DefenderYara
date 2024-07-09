
rule Trojan_Win32_GenSHCode_GMP_MTB{
	meta:
		description = "Trojan:Win32/GenSHCode.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 ac 68 95 08 54 c9 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c7 01 88 47 ff 51 83 c4 04 ?? ?? ?? ?? c7 44 24 ?? 11 88 a6 44 4a 83 c2 02 68 17 4d b1 44 83 c4 04 49 85 c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}