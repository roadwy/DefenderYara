
rule Trojan_Win64_Midie_MDD_MTB{
	meta:
		description = "Trojan:Win64/Midie.MDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 32 c9 41 32 ca 41 88 4c 24 01 49 8d 47 fe 83 e0 07 0f b6 8c 30 ?? ?? ?? ?? c0 e9 04 c0 e2 04 0a ca 41 32 8c 37 ?? ?? ?? ?? 32 cb 41 32 c8 41 88 4c 24 02 49 83 c7 05 49 83 c5 05 4d 8d 64 24 05 49 83 fd 1a 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}