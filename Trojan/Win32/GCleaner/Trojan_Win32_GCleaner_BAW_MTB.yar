
rule Trojan_Win32_GCleaner_BAW_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b d6 7c ?? 5f 83 fe 2d 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}