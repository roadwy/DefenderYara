
rule Trojan_Win64_Dacic_ADI_MTB{
	meta:
		description = "Trojan:Win64/Dacic.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c8 4d 03 ca 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 b8 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 39 41 0f b6 c0 2a c1 04 34 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}