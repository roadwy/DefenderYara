
rule Trojan_Win64_Dbadur_GCM_MTB{
	meta:
		description = "Trojan:Win64/Dbadur.GCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 f1 4e 12 76 ?? 20 41 76 ?? 20 41 76 ?? 20 41 7f e8 ?? ?? ?? ?? 20 41 24 e5 25 40 6e ?? 20 41 24 e5 24 40 7c ?? 20 41 24 e5 23 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}