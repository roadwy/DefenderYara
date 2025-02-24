
rule Trojan_Win64_Caynamer_ACAY_MTB{
	meta:
		description = "Trojan:Win64/Caynamer.ACAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 4f ec c4 4e 4d 8d 40 01 f7 eb c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 0f b6 c3 ff c3 2a c1 04 38 41 30 40 ff 83 fb 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}