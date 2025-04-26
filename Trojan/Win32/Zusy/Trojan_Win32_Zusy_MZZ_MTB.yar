
rule Trojan_Win32_Zusy_MZZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f b6 84 34 28 01 00 00 88 84 1c 28 01 00 00 88 8c 34 28 01 00 00 0f b6 84 1c 28 01 00 00 8b 4c 24 1c 03 c2 0f b6 c0 89 74 24 18 0f b6 84 04 ?? ?? ?? ?? 30 04 39 47 3b 7d 0c 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}