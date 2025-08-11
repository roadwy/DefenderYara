
rule Trojan_Win32_Remcos_AROS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AROS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 33 f6 8b f8 56 56 56 6a 01 56 ff 15 ?? ?? ?? ?? 56 68 00 00 00 80 56 56 8b e8 68 b4 d9 46 00 55 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}