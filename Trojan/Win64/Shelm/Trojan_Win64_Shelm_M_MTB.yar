
rule Trojan_Win64_Shelm_M_MTB{
	meta:
		description = "Trojan:Win64/Shelm.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 37 41 8b de 49 03 f1 48 8d 7f ?? 0f be 0e 48 ff c6 c1 cb ?? 03 d9 84 c9 } //2
		$a_03_1 = {41 8d 0c 30 45 03 ?? 80 34 ?? ?? 44 3b c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}