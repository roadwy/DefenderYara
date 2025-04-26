
rule Trojan_Win32_Bunitu_GKM_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.GKM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 30 f7 d8 8b 8d 7c ff ff ff 0f be 11 2b d0 8b 85 7c ff ff ff 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}