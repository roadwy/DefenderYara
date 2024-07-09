
rule Trojan_Win32_Emotet_DVP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 3b 33 c8 8d 9b ?? ?? ?? ?? 2b f1 4a 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}