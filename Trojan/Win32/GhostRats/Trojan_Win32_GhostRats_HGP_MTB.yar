
rule Trojan_Win32_GhostRats_HGP_MTB{
	meta:
		description = "Trojan:Win32/GhostRats.HGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ce 5a ae d2 34 b7 ff 94 35 3f 06 5c c0 df a1 e7 36 0c 3c 00 37 0c 16 30 2d fc 6f d2 cb 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}