
rule Trojan_Win32_Tofsee_RTA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}