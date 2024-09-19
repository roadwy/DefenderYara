
rule Trojan_Win32_Yakes_SPON_MTB{
	meta:
		description = "Trojan:Win32/Yakes.SPON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 50 89 b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 30 04 3b 83 7d 08 0f 59 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}