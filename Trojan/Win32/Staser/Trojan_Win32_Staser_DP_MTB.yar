
rule Trojan_Win32_Staser_DP_MTB{
	meta:
		description = "Trojan:Win32/Staser.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3b 7d 0c a9 00 00 80 00 ff 15 ?? ?? ?? 00 6a 01 ff 75 14 ff 15 ?? ?? ?? 00 85 c0 74 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}