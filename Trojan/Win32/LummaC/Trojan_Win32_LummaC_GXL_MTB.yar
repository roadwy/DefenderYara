
rule Trojan_Win32_LummaC_GXL_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 c4 50 e8 ?? ?? ?? ?? 8a 45 c4 30 04 37 59 83 fb 0f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}