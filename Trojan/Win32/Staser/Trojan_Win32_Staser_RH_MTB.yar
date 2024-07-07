
rule Trojan_Win32_Staser_RH_MTB{
	meta:
		description = "Trojan:Win32/Staser.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3d 02 01 00 00 0c 01 90 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}