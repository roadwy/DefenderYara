
rule Trojan_Win32_RisePro_GNF_MTB{
	meta:
		description = "Trojan:Win32/RisePro.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 cb d0 c1 80 c1 01 80 f1 3e 80 c1 04 f6 d9 32 d9 8d 4c 0c 08 88 11 8d 64 24 08 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}