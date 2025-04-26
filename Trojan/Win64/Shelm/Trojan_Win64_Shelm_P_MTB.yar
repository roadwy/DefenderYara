
rule Trojan_Win64_Shelm_P_MTB{
	meta:
		description = "Trojan:Win64/Shelm.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f be 0c 39 b8 ?? ?? ?? ?? 49 ff c1 f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c2 69 d2 ?? ?? ?? ?? 2b ca 80 c1 4f 41 30 0b 25 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}