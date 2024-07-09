
rule Trojan_Win32_Emotet_DCE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 de 21 fe 8b 7c 24 ?? 32 14 37 8b 74 24 ?? 81 c6 ?? ?? ?? ?? 8b 7c 24 ?? 88 14 0f 01 f1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}