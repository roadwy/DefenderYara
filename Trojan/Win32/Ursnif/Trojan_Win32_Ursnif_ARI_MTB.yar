
rule Trojan_Win32_Ursnif_ARI_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 37 80 c9 9c 88 d5 0f b6 d5 8b 7c 24 2c 8b 44 24 10 8a 2c 07 88 4c 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}