
rule Trojan_Win64_Tedy_AVD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 83 f2 ?? 41 88 14 04 48 ff c0 48 83 f8 ?? 75 } //2
		$a_03_1 = {8a 14 01 83 f2 ?? 88 14 06 48 ff c0 48 83 f8 ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}