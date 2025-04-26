
rule Trojan_Win64_Lazy_HHM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.HHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 b8 01 00 00 00 2a c2 0f be c0 6b c8 39 41 02 c8 41 ff c0 41 30 49 ff 41 83 f8 11 7c ca } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}