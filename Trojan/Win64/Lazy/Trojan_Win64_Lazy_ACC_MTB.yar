
rule Trojan_Win64_Lazy_ACC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ACC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 33 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 1d 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}