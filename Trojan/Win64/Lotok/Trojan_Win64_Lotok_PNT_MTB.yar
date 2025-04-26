
rule Trojan_Win64_Lotok_PNT_MTB{
	meta:
		description = "Trojan:Win64/Lotok.PNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 01 49 ff c0 49 ff c1 41 30 40 ff 49 83 ea 01 75 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}