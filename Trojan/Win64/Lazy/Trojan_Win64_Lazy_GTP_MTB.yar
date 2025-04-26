
rule Trojan_Win64_Lazy_GTP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f6 db 41 0f 95 c3 4f 8d 9c 1b ?? ?? ?? ?? c1 6c 24 ?? 4c 48 c7 44 24 ?? 80 5b 76 e7 4c 8b 5c 24 ?? 48 81 74 24 ?? 34 72 b2 a5 80 74 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}