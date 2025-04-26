
rule Trojan_Win64_Mikey_GZN_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 26 8b 34 df 63 41 ?? ?? bd ?? ?? ?? ?? 6d 44 21 6f ?? 86 5d ?? 32 4c c3 ?? 30 28 32 ec 08 52 ?? 54 5a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}