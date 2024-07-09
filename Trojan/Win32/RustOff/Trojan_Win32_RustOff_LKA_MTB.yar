
rule Trojan_Win32_RustOff_LKA_MTB{
	meta:
		description = "Trojan:Win32/RustOff.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 27 77 ?? 8b 91 ?? ?? ?? 00 33 14 08 89 94 0c ?? ?? 00 00 83 c1 04 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}