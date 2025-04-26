
rule Trojan_Win32_Zusy_GAD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 3a 42 01 c6 81 ee ?? ?? ?? ?? 39 da 75 ?? 81 e8 ?? ?? ?? ?? c3 48 09 f0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}