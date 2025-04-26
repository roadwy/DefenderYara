
rule Trojan_Win32_DarkGate_NNJ_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.NNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 33 d2 8b c7 f7 75 ?? 47 8a 04 32 8b 55 ?? 32 04 11 88 01 8b 45 b0 8b 8d ?? ?? ff ff 3b 7d ac 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}