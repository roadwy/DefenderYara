
rule Trojan_Win32_Stealc_AMAA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 33 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8a 4c 24 ?? 88 0c 33 83 ff 0f 75 0f 6a 00 8d 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}