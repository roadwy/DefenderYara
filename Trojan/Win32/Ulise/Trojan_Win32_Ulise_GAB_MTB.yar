
rule Trojan_Win32_Ulise_GAB_MTB{
	meta:
		description = "Trojan:Win32/Ulise.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c6 89 45 08 33 c9 8d 14 30 8a 04 0f 41 88 02 8d 52 04 83 f9 04 ?? ?? 8b 45 08 46 83 c7 04 3b f3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}