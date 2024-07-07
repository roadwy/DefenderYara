
rule Trojan_Win32_Redline_PCC_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 89 a0 94 47 00 88 4d fb 0f b6 45 fb 8b 0d 10 96 47 00 03 8d 10 5d ff ff 0f be 11 33 d0 a1 10 96 47 00 03 85 10 5d ff ff 88 10 e9 0b ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}