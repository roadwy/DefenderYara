
rule Trojan_Win64_Injector_SXG_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 0f b7 02 8d 48 ?? 66 83 f9 19 8d 50 ?? 66 0f 47 d0 41 8d 40 ?? 66 83 f8 19 41 8d 48 ?? 66 41 0f 47 c8 66 3b d1 ?? ?? 41 0f b7 41 ?? 49 83 c1 02 49 83 c2 02 66 85 c0 } //30
		$a_01_1 = {46 0f b6 44 0c 40 49 8b c9 48 8b c6 49 f7 e1 48 c1 ea 03 48 6b c2 0f 48 2b c8 0f b6 0c 29 48 03 cb 49 03 c8 0f b6 d9 0f b6 44 1c 40 42 88 44 0c 40 49 ff c1 44 88 44 1c 40 49 81 f9 00 01 00 00 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}