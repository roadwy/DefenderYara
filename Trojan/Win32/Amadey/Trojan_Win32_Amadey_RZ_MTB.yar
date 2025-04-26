
rule Trojan_Win32_Amadey_RZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8d 04 0a 33 d2 f7 35 ?? ?? ?? ?? 03 d6 8b 75 ?? 8b ce 83 7e ?? 10 72 ?? 8b 0e 8a 02 88 04 19 43 89 5d ?? 3b 5d ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}