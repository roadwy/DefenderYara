
rule Trojan_Win64_Rhadamanthys_KKL_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.KKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 10 48 8d 54 24 40 48 8b 44 24 58 44 30 10 49 8b c6 83 e0 0f 48 03 c8 41 0f b6 04 24 32 01 32 85 ?? ?? ?? ?? 88 01 48 8d 4c 24 60 e8 ff f9 ff ff 4c 8b a5 ?? ?? ?? ?? 43 30 04 34 4d 8b f5 49 81 fd 00 fe 07 00 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}