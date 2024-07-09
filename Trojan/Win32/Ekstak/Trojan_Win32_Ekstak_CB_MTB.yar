
rule Trojan_Win32_Ekstak_CB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c6 8b f0 33 ?? 3d 4e e6 40 bb 74 0c f7 05 ?? ?? ?? ?? 00 00 ff ff 75 05 b8 4f e6 40 bb a3 ?? ?? ?? ?? f7 d0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}