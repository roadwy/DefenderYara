
rule Trojan_Win32_Androm_RW_MTB{
	meta:
		description = "Trojan:Win32/Androm.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c2 01 89 95 90 01 04 83 bd 90 01 04 05 7d 90 01 01 8b 85 90 01 04 99 b9 03 00 00 00 f7 f9 8b 45 90 01 01 0f be 0c 10 8b 95 90 01 04 0f b6 44 15 90 01 01 33 c1 8b 8d 90 01 04 88 44 0d 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}