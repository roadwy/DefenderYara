
rule Trojan_Win32_Copak_GNI_MTB{
	meta:
		description = "Trojan:Win32/Copak.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 1a 81 c2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 5e 81 c0 ?? ?? ?? ?? 39 ca 75 ?? c3 21 c0 29 c6 8d 1c 1f 8b 1b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}