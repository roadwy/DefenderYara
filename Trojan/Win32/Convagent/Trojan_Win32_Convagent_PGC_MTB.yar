
rule Trojan_Win32_Convagent_PGC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.PGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 42 d8 f6 c1 7f b9 ?? ?? ?? ?? 89 5d a0 0f 95 c1 0f b6 db f6 c3 7f 89 5d a8 b8 ?? ?? ?? ?? 0f 95 c0 03 c8 8b 45 9c c1 e8 07 03 c8 8b c3 } //2
		$a_01_1 = {4e 59 47 70 75 4b 4b 69 55 37 3f 5b 30 6b 74 } //3 NYGpuKKiU7?[0kt
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}