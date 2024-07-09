
rule Trojan_Win32_StealC_YAA_MTB{
	meta:
		description = "Trojan:Win32/StealC.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 01 d0 0f b6 00 89 c2 8b 45 14 89 d1 31 c1 8b 55 ?? 8b 45 ?? 01 d0 89 ca 88 10 83 45 } //1
		$a_03_1 = {88 45 e2 8b 55 f0 8b 45 08 01 d0 0f b6 00 32 45 e2 88 45 e1 8b 55 f0 8b 45 0c 01 c2 0f b6 45 ?? 88 02 83 45 f0 01 8b 45 f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}