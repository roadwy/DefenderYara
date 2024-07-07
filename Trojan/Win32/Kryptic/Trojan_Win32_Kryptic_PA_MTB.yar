
rule Trojan_Win32_Kryptic_PA_MTB{
	meta:
		description = "Trojan:Win32/Kryptic.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 fe 8b 4d 90 01 01 8a 3c 11 8b 75 90 01 01 88 3c 31 88 1c 11 0f b6 0c 31 8b 75 90 01 01 01 f1 81 e1 ff 00 00 00 8b 75 90 01 01 8b 5d 90 01 01 8a 1c 1e 8b 75 90 01 01 32 1c 0e 8b 4d 90 01 01 8b 75 90 01 01 88 1c 31 8b 4d 90 01 01 39 cf 8b 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}