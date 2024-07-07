
rule Trojan_Win32_Azorult_SK_MSR{
	meta:
		description = "Trojan:Win32/Azorult.SK!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 78 fd ff ff 03 55 fc 8b 85 74 fd ff ff 03 45 fc 8a 88 3b 2d 0b 00 88 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}