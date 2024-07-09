
rule Trojan_Win32_Sednit_LK_MTB{
	meta:
		description = "Trojan:Win32/Sednit.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 02 32 44 39 ?? 32 ?? ?? 88 04 1f 4f 8b 0e 83 ff ff 7f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}