
rule Trojan_Win32_Staser_RTA_MTB{
	meta:
		description = "Trojan:Win32/Staser.RTA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 53 83 ec 0c 8b 5d 14 6a 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}