
rule Trojan_Win32_Zenapak_CCEN_MTB{
	meta:
		description = "Trojan:Win32/Zenapak.CCEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c2 81 c2 ?? ?? ?? ?? 8b 03 0f b7 12 31 c2 01 ca 81 fe ?? ?? ?? ?? 89 d0 89 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}