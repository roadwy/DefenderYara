
rule Trojan_Win32_Stealc_CF_MTB{
	meta:
		description = "Trojan:Win32/Stealc.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 37 8a 80 ?? ?? ?? ?? 0f be 5c 37 01 8a 9b 08 f8 40 00 c0 eb ?? c0 e0 ?? 0a c3 88 01 } //5
		$a_03_1 = {0f be 44 37 02 0f be 5c 37 01 8a 9b ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? c0 e3 ?? c0 e8 ?? 0a c3 88 41 01 } //5
		$a_03_2 = {0f be 5c 37 02 0f be 44 37 03 8a 9b 08 f8 40 00 c0 e3 ?? 0a ?? ?? ?? ?? ?? 83 c6 ?? 88 59 02 83 c1 ?? 3b 75 08 7c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}