
rule Trojan_Win32_Graftor_BA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 f8 33 d2 b9 0e 00 00 00 f7 f1 8b 45 f4 0f b6 0c 10 8b 55 f8 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f8 88 81 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}