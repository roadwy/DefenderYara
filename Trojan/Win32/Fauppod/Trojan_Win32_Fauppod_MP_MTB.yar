
rule Trojan_Win32_Fauppod_MP_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 83 c7 01 ?? 42 ?? 83 e9 01 85 c9 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}