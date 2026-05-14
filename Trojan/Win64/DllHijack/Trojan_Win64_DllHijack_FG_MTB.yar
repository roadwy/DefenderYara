
rule Trojan_Win64_DllHijack_FG_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 f8 48 8b 45 d0 48 01 d0 0f b6 10 48 8b 4d f8 48 8b 45 d0 48 01 c8 83 f2 ?? 88 10 48 83 45 d0 01 } //1
		$a_03_1 = {48 8b 55 d8 48 8b 45 e8 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 e8 48 01 c8 83 f2 ?? 88 10 48 83 45 e8 01 48 8b 45 e8 48 3b 45 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}