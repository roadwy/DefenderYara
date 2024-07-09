
rule Trojan_Win32_Fragtor_SPK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 68 74 12 00 00 6a 00 55 ff 15 ?? ?? ?? ?? 85 c0 0f 84 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}