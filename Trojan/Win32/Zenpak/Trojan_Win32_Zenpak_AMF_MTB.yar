
rule Trojan_Win32_Zenpak_AMF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 45 [0-90] a2 ?? ?? ?? ?? c7 05 [0-90] 0f b6 05 ?? ?? ?? ?? 83 c4 04 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}