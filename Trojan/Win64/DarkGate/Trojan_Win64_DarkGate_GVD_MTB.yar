
rule Trojan_Win64_DarkGate_GVD_MTB{
	meta:
		description = "Trojan:Win64/DarkGate.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 d0 0f b6 0c 32 41 88 0c 31 44 88 14 32 41 0f b6 14 31 49 03 d2 0f b6 ca 0f b6 0c 31 41 30 0b 49 ff c3 48 83 eb 01 75 a3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}