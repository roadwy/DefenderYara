
rule Trojan_Win32_Tedy_MSM_MTB{
	meta:
		description = "Trojan:Win32/Tedy.MSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 01 69 f6 95 e9 d1 5b 69 c0 95 e9 d1 5b 8b d8 c1 eb 18 33 d8 69 db ?? ?? ?? ?? 33 f3 83 ea 04 83 c1 04 4f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}