
rule Trojan_Win64_Latrodectus_DK_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c6 99 41 ff c2 41 f7 fd 41 ff c6 34 35 0f b6 c8 41 0f b6 80 11 0d 00 00 0f af c1 0f b7 ce 41 88 80 11 0d 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}