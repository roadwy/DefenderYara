
rule Trojan_Win32_Penguish_GTB_MTB{
	meta:
		description = "Trojan:Win32/Penguish.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 51 51 83 c4 04 81 c9 ?? ?? ?? ?? 59 51 51 83 c4 04 81 c9 ?? ?? ?? ?? 59 56 81 ee ?? ?? ?? ?? 81 f6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}