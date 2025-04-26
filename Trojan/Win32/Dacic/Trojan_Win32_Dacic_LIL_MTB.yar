
rule Trojan_Win32_Dacic_LIL_MTB{
	meta:
		description = "Trojan:Win32/Dacic.LIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b ca 8a 14 19 32 d3 8d 04 19 8a 8d a8 fe ff ff 32 d1 8d 8d 94 fe ff ff 88 10 8d 95 20 fe ff ff c7 85 28 ?? ?? ?? 10 94 40 00 89 bd 20 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}