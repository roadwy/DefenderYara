
rule Trojan_Win64_Lazy_SFD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 0f b6 04 08 32 02 41 88 04 08 41 ff c2 49 ff c0 49 63 c2 48 3b 43 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}