
rule Trojan_Win64_Emotet_BS_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 ff c3 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 41 32 4c 3e ?? 88 4f ?? 48 ff ce 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}