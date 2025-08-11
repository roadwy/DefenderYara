
rule Trojan_Win64_Tedy_ATYE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 03 40 32 c6 88 44 24 30 48 3b bd ?? ?? ?? ?? 74 0e 88 07 48 ff c7 48 89 bd ?? ?? ?? ?? eb 1b 4c 8d 44 24 30 48 8b d7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}