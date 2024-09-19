
rule Trojan_Win32_Lummac_GA_MTB{
	meta:
		description = "Trojan:Win32/Lummac.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ce 31 c4 cf c7 40 ?? 3a cd fe cb c7 40 ?? 36 c9 3c c7 c7 40 ?? 32 c5 c4 c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}