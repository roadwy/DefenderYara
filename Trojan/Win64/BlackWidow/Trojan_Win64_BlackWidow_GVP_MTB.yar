
rule Trojan_Win64_BlackWidow_GVP_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c1 ea 04 48 6b c2 11 48 2b c8 48 8b 45 1f 0f b6 4c 0d 37 43 32 4c 10 ff 41 88 4c 00 ff 3b 5d 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}