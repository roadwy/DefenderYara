
rule Trojan_Win32_IcedID_DSP_MTB{
	meta:
		description = "Trojan:Win32/IcedID.DSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 01 03 fe 89 3d 90 01 04 39 15 90 01 04 76 90 01 01 29 35 90 01 04 05 28 57 93 01 a3 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}