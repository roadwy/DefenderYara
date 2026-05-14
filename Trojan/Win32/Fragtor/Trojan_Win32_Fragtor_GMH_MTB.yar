
rule Trojan_Win32_Fragtor_GMH_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 00 88 45 b0 8b 45 e8 25 ff 00 00 00 8a 4d b0 32 c8 88 4d b0 8b 45 e0 8a 4d b0 32 4c 05 b8 88 4d b0 8b 45 e0 40 89 45 e0 8b 45 fc 03 45 e8 8a 4d b0 88 08 83 7d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}