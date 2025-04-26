
rule Trojan_Win32_SmokeLoader_KAL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 10 c7 05 34 52 28 02 ff ff ff ff 8b 44 24 10 29 44 24 14 81 c7 47 86 c8 61 4d 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}