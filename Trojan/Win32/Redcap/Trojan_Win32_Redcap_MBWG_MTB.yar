
rule Trojan_Win32_Redcap_MBWG_MTB{
	meta:
		description = "Trojan:Win32/Redcap.MBWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 c4 f0 b8 4c d1 43 00 e8 30 9a fc ff 33 c0 55 68 75 07 44 00 64 ff 30 64 89 20 e8 ad bc ff ff 33 c0 5a 59 59 64 89 10 68 7c 07 44 00 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}