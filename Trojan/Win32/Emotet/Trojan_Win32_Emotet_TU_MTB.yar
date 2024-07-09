
rule Trojan_Win32_Emotet_TU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.TU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8a 03 83 c4 04 8a 54 14 14 32 c2 88 03 43 4d 75 93 8b 84 24 ?? ?? ?? ?? 5b 5d 5e 5f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}