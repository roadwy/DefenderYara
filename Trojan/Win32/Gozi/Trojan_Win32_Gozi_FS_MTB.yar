
rule Trojan_Win32_Gozi_FS_MTB{
	meta:
		description = "Trojan:Win32/Gozi.FS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 bb 30 00 00 00 99 f7 fb 8a 82 8c 22 43 00 32 81 2c 61 42 00 8b 55 f8 88 04 0a 41 3b 4d fc 72 de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}