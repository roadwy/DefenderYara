
rule Trojan_Win32_Zusy_AMMH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}