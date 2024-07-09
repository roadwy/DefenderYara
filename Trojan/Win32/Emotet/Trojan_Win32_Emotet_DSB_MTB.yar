
rule Trojan_Win32_Emotet_DSB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 8a 4c 15 00 30 08 90 09 04 00 0f b6 4d } //1
		$a_81_1 = {32 67 61 49 4f 36 56 78 73 36 50 4f 64 4e 6e 47 72 48 59 43 41 55 6f 72 56 72 49 48 67 41 6b 66 72 68 } //1 2gaIO6Vxs6POdNnGrHYCAUorVrIHgAkfrh
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}