
rule Trojan_Win32_Adload_RDS_MTB{
	meta:
		description = "Trojan:Win32/Adload.RDS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 03 00 00 00 f7 f1 8b 45 dc 0f be 0c 10 8b 55 f4 0f b6 44 15 ec 33 c1 8b 4d f4 88 44 0d ec eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}