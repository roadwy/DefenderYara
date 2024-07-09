
rule Trojan_Win32_Polyransom_SG_MTB{
	meta:
		description = "Trojan:Win32/Polyransom.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {e9 00 00 00 00 32 c2 88 07 ?? ?? ?? ?? ?? ?? 83 f9 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}