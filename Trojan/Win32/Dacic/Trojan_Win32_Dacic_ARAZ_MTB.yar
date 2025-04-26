
rule Trojan_Win32_Dacic_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Dacic.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 c5 00 00 00 00 2b d0 03 d2 2b ca 8a 81 ?? ?? ?? ?? 88 44 1e ff 3b f7 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}