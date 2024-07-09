
rule Trojan_Win32_Injector_DSK_MTB{
	meta:
		description = "Trojan:Win32/Injector.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e0 33 d2 b9 04 00 00 00 f7 f1 8b 45 e8 0f be 0c 10 8b 55 e0 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d e0 88 81 ?? ?? ?? ?? eb c4 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}