
rule Trojan_Win32_RedLineStealer_EB_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 00 0f be 8d 5b ff ff ff 09 c8 88 c1 8b 85 60 ff ff ff 88 08 0f b7 85 f6 fe ff ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}