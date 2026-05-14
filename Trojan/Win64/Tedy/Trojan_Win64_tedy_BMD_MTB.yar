
rule Trojan_Win64_tedy_BMD_MTB{
	meta:
		description = "Trojan:Win64/tedy.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 ?? 48 01 c8 83 f2 65 88 10 83 45 fc ?? 8b 45 fc 48 98 48 3b 45 18 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}