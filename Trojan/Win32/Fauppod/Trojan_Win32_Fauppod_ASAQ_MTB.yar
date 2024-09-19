
rule Trojan_Win32_Fauppod_ASAQ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.ASAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d [0-04] a2 [0-04] 30 c8 a2 [0-04] 8b 15 [0-04] 81 c2 [0-04] 89 15 [0-04] 88 45 ff c7 05 [0-08] 8a 45 ff 0f b6 c0 83 c4 04 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}