
rule Trojan_Win64_BlackWidow_GVF_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 0c 02 41 33 48 78 49 8b 80 b0 00 00 00 41 89 0c 02 49 83 c2 04 8b 05 ?? ?? ?? ?? 41 8b 50 74 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}