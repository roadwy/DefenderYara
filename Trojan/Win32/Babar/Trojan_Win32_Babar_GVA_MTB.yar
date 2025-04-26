
rule Trojan_Win32_Babar_GVA_MTB{
	meta:
		description = "Trojan:Win32/Babar.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 2b ce 8b d7 8d 9b ?? ?? ?? ?? 8a 1c 01 80 f3 88 88 18 40 4a 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}