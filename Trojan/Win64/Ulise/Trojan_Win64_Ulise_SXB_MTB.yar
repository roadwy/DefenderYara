
rule Trojan_Win64_Ulise_SXB_MTB{
	meta:
		description = "Trojan:Win64/Ulise.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 13 ?? 48 8d 5b 01 34 aa 88 44 1d ?? 48 83 e9 01 75 eb } //20
		$a_03_1 = {0f 57 c8 48 8d 4d ?? f3 0f 6f 05 ?? ?? ?? ?? 66 0f 6f d6 0f 57 d0 f3 0f 7f 55 ?? f3 0f 7f 4d } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}