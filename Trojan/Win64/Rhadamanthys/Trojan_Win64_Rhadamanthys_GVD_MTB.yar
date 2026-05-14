
rule Trojan_Win64_Rhadamanthys_GVD_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 8b 44 24 08 41 89 c5 45 28 e5 44 32 6c 24 04 41 f6 dd 31 c0 49 39 d7 0f 92 c0 c1 e0 03 8d 04 40 4a 8b b4 08 ?? ?? ?? ?? 4c 01 d6 4c 89 f8 ff e6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Rhadamanthys_GVD_MTB_2{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 8b 55 d8 48 8b 45 f8 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 f8 48 01 c8 83 ea 4c 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 d0 72 d3 } //2
		$a_01_1 = {48 8b 55 d8 48 8b 45 f0 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 f0 48 01 c8 83 f2 39 88 10 4d 8d 6d } //1
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}