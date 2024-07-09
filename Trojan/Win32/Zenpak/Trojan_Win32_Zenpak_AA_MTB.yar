
rule Trojan_Win32_Zenpak_AA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d fa 0f b6 55 fa 0f b6 75 fb 31 f2 88 ?? 0f b6 ?? 83 c4 ?? 5e 5d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}