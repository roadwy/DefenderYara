
rule Trojan_Win32_LummaC_AMAA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 6d fc 46 8b 45 08 8a 4d fc 03 c2 30 08 42 3b d7 7c ?? 5e 83 ff 2d 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}