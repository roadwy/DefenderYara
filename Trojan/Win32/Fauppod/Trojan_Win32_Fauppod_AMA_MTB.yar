
rule Trojan_Win32_Fauppod_AMA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 88 0d [0-28] 30 c8 [0-14] c7 05 [0-14] 0f b6 c0 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}