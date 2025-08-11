
rule Trojan_Win32_Stealer_EAOZ_MTB{
	meta:
		description = "Trojan:Win32/Stealer.EAOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c6 0f b6 d3 03 d0 81 e2 ff 00 00 00 8b f2 8a 86 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 81 f9 39 0f 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}