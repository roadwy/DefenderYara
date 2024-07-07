
rule Trojan_Win32_Tofsee_RT_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 54 24 90 01 01 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 44 24 90 01 01 8d 0c 37 33 c1 31 44 24 90 01 01 83 3d 90 01 04 42 c7 05 90 01 04 36 06 ea e9 89 44 24 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}